// Command vpn manages the VPN registry: servers, users, subscriptions.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/build"
	"github.com/OXI-717/ai-agents-relay-kit/internal/cf"
	"github.com/OXI-717/ai-agents-relay-kit/internal/deploy"
	"github.com/OXI-717/ai-agents-relay-kit/internal/external"
	geopins "github.com/OXI-717/ai-agents-relay-kit/internal/geo"
	"github.com/OXI-717/ai-agents-relay-kit/internal/keychain"
	"github.com/OXI-717/ai-agents-relay-kit/internal/mask"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/remote"
	"github.com/OXI-717/ai-agents-relay-kit/internal/users"
	"github.com/OXI-717/ai-agents-relay-kit/internal/verify"
)

const distDir = "dist"

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "vpn: "+f+"\n", a...); os.Exit(1) }

func mustLoad(dir string) *registry.Registry {
	r, err := registry.Load(dir)
	if err != nil {
		die("%v", err)
	}
	return r
}

func mustValid(r *registry.Registry) {
	if errs := r.Validate(); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "  ✗", e)
		}
		die("registry invalid (%d errors)", len(errs))
	}
}

func saveAll(r *registry.Registry) {
	if err := registry.SaveSecrets(r.Dir, r.Secrets); err != nil {
		die("%v", err)
	}
	if err := registry.SaveUsers(r.Dir, r.Users); err != nil {
		die("%v", err)
	}
	if err := registry.SaveServers(r.Dir, r.Servers); err != nil {
		die("%v", err)
	}
}

func server(r *registry.Registry, id string) registry.Server {
	s, ok := r.ServerByID(id)
	if !ok {
		die("unknown server %s", id)
	}
	return s
}

func userByID(r *registry.Registry, id string) registry.User {
	for _, u := range r.Users {
		if u.ID == id {
			return u
		}
	}
	die("unknown user %s", id)
	return registry.User{}
}

func xrayBin() string {
	p, _ := filepath.Abs("bin/xray")
	if _, err := os.Stat(p); err != nil {
		die("bin/xray missing (plan Task 0 Step 5)")
	}
	return p
}

func runner(r *registry.Registry) remote.Runner {
	return remote.NewSSH(filepath.Join(r.Dir, "known_hosts"))
}

func writeUserArtifacts(r *registry.Registry, u registry.User) {
	txt, png, err := build.Bundle(r, u)
	if err != nil {
		die("%v", err)
	}
	tok := r.Secrets.Users[u.ID].Token
	base := r.Cloudflare.SubBaseURL + "/s/" + tok
	links := fmt.Sprintf("INCY: %s?f=incy\nHapp: %s?f=happ\n", base, base)
	files := map[string][]byte{
		"users/" + u.ID + "/subscription.txt": []byte(links),
		"users/" + u.ID + "/bundle.txt":       txt,
		"users/" + u.ID + "/bundle.png":       png,
	}
	if err := build.WriteDist(distDir, files); err != nil {
		die("%v", err)
	}
	fmt.Printf("%s: token %s; файлы в %s/users/%s/ (subscription.txt, bundle.txt, bundle.png)\n", u.ID, mask.Secret(tok), distDir, u.ID)
}

func cfKVResult(r *registry.Registry) (*cf.KV, error) {
	tok, err := keychain.Get("cf-token")
	if err != nil {
		return nil, err
	}
	return &cf.KV{Account: r.Cloudflare.AccountID, Namespace: r.Cloudflare.KVNamespaceID, Token: tok}, nil
}
func cfKV(r *registry.Registry) *cf.KV {
	kv, err := cfKVResult(r)
	if err != nil {
		die("%v", err)
	}
	return kv
}

func deployServers(ctx context.Context, r *registry.Registry, only string, mode deploy.Mode) bool {
	xray, _ := filepath.Abs("bin/xray")
	chk := verify.New(r, xray)
	id := deploy.ReleaseID(time.Now())
	ok := true
	for _, res := range deploy.Servers(ctx, r, runner(r), chk, only, mode, id) {
		if res.Err != nil {
			if !res.Warning {
				ok = false
			}
			if res.Warning {
				fmt.Printf("  warning: %s: stop unconfirmed: %v\n", res.Server, res.Err)
				continue
			}
			fmt.Printf("  ✗ %s: %v (rolled back: %v)\n", res.Server, res.Err, res.RolledBack)
		} else {
			fmt.Printf("  ✓ %s: %s\n", res.Server, res.Status)
		}
	}
	return ok
}

func deploySubs(ctx context.Context, r *registry.Registry) {
	// Before publishing subscriptions that point clients at the geo files, prove
	// the pinned assets still match their sha256 and cover the used categories.
	if err := geopins.Check(ctx, r.Pins, r.Routing); err != nil {
		die("geo pins: %v", err)
	}
	w, d, err := deploy.Subs(ctx, r, cfKV(r), time.Now().Unix())
	if err != nil {
		die("subs: %v", err)
	}
	fmt.Printf("  ✓ subscriptions: %d written, %d deleted\n", w, d)
}

func main() {
	regDir := flag.String("registry", "registry", "registry directory")
	only := flag.String("server", "", "only this server")
	force := flag.Bool("force", false, "overwrite existing keys")
	load := flag.Int("load", 0, "verify: parallel requests + 20MB download")
	fromClip := flag.Bool("from-clipboard", false, "import: read pbpaste")
	geo := flag.Bool("geo", false, "validate: also download geo files and verify pins")
	flag.Parse()
	a := flag.Args()
	if len(a) == 0 {
		die("usage: vpn [--registry dir] validate|server|uuids|user|import|deploy|verify ...")
	}
	if mutatesRegistry(a) {
		lock, err := lockRegistry(*regDir)
		if err != nil {
			die("%v", err)
		}
		defer lock.Close()
	}
	ctx := context.Background()
	r := mustLoad(*regDir)

	switch strings.Join(a[:min(2, len(a))], " ") {
	case "validate":
		mustValid(r)
		if *geo {
			if err := geopins.Check(ctx, r.Pins, r.Routing); err != nil {
				die("geo pins: %v", err)
			}
			fmt.Println("geo pins verified")
		}
		fmt.Println("registry OK")
	case "server keys":
		if err := users.ServerKeys(r, a[2], *force); err != nil {
			die("%v", err)
		}
		saveAll(r)
		fmt.Printf("%s: new Reality keys, public %s\n", a[2], server(r, a[2]).Reality.PublicKey)
	case "server probe-target":
		s := server(r, a[2])
		for _, d := range a[3:] {
			res, err := deploy.ProbeTarget(ctx, runner(r), s, d)
			if err != nil {
				fmt.Printf("  ✗ %s: %v\n", d, err)
				continue
			}
			fmt.Printf("  %s tls1.3=%v h2=%v connect=%dms\n", d, res.TLS13, res.H2, res.ConnectMS)
		}
	case "server bootstrap":
		s := server(r, a[2])
		helper, err := os.ReadFile("deploy/vpn-helper.sh")
		if err != nil {
			die("%v", err)
		}
		pub, err := os.ReadFile(os.ExpandEnv("$HOME/.ssh/relaykit_ed25519.pub"))
		if err != nil {
			die("%v", err)
		}
		if err := deploy.Bootstrap(ctx, runner(r), s, helper, strings.TrimSpace(string(pub))); err != nil {
			die("%v", err)
		}
		fmt.Printf("%s: bootstrap ok\n", s.ID)
	case "uuids fill":
		toks, err := users.FillTokens(r)
		if err != nil {
			die("%v", err)
		}
		added := users.Fill(r)
		saveAll(r)
		fmt.Printf("tokens for: %s; added %d pairs: %s\n", strings.Join(toks, ", "), len(added), strings.Join(added, ", "))
	case "user add":
		if len(a) < 4 {
			die("usage: vpn user add <id> <Имя>")
		}
		if err := users.Add(r, a[2], a[3]); err != nil {
			die("%v", err)
		}
		mustValid(r)
		saveAll(r)
		writeUserArtifacts(r, userByID(r, a[2]))
		fmt.Println("дальше: vpn deploy (удалит dist), затем vpn user bundle <id> → передать человеку → vpn dist clean")
	case "user revoke":
		if len(a) != 3 && !(len(a) == 4 && a[3] == "--retry") {
			die("usage: vpn user revoke <id> [--retry]")
		}
		// A missing local xray must become a per-node verify failure, never an early exit.
		xray, _ := filepath.Abs("bin/xray")
		results, err := revokeUser(ctx, r, a[2], func() (*cf.KV, error) { return cfKVResult(r) }, runner(r), verify.New(r, xray))
		fmt.Println("stage | result")
		for _, res := range results {
			if res.Err != nil {
				fmt.Printf("%s | unconfirmed: %v\n", res.Step, res.Err)
			} else {
				fmt.Printf("%s | ok\n", res.Step)
			}
		}
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("%s: revoked everywhere\n", a[2])
	case "user bundle":
		writeUserArtifacts(r, userByID(r, a[2]))
	case "import":
		if !*fromClip {
			die("usage: vpn import --from-clipboard")
		}
		out, err := exec.Command("pbpaste").Output()
		if err != nil {
			die("pbpaste: %v", err)
		}
		ps, err := external.ParseLinks(string(out))
		if err != nil {
			die("%v", err)
		}
		seen := map[string]bool{}
		for _, e := range r.External {
			seen[e.ID] = true
		}
		for id := range r.Secrets.External {
			seen[id] = true
		}
		for i, p := range ps {
			if seen[p.ID] {
				die("external id already exists at line %d", i+1)
			}
			seen[p.ID] = true
		}
		for _, p := range ps {
			admin := ""
			for _, u := range r.ActiveUsers() {
				if u.Admin {
					admin = u.ID
				}
			}
			r.External = append(r.External, registry.External{ID: p.ID, Label: "ext · " + p.Label, Owner: "imported " + time.Now().Format("2006-01-02"), ShareWith: []string{admin}})
			r.Secrets.External[p.ID] = p.Link
			fmt.Printf("  + %s (%s)\n", p.ID, p.Host)
		}
		if err := registry.SaveExternal(r.Dir, r.External); err != nil {
			die("%v", err)
		}
		saveAll(r)
	case "deploy", "deploy servers", "deploy subs":
		mustValid(r)
		part := ""
		if len(a) > 1 {
			part = a[1]
		}
		if part != "subs" && !deployServers(ctx, r, *only, deploy.StopOnError) {
			die("deploy stopped")
		}
		if part != "servers" {
			deploySubs(ctx, r)
		}
		if part == "" {
			// dist/users holds tokens and raw links; `vpn user bundle` regenerates them on demand
			if err := os.RemoveAll(distDir); err != nil {
				die("dist cleanup: %v", err)
			}
		}
	case "dist clean":
		if err := os.RemoveAll(distDir); err != nil {
			die("dist cleanup: %v", err)
		}
		fmt.Println("dist removed")
	case "verify":
		mustValid(r)
		if *only != "" {
			s := server(r, *only)
			if !s.Enabled {
				die("%s: server disabled", *only)
			}
		}
		chk := verify.New(r, xrayBin())
		chk.Report = func(key, ip string, err error) {
			if err != nil {
				fmt.Printf("  ✗ %s: %v\n", key, err)
			} else {
				fmt.Printf("  ✓ %s: expected exit %s, ok\n", key, ip)
			}
		}
		failed := false
		for _, s := range r.Servers {
			if !s.Enabled || (*only != "" && s.ID != *only) {
				continue
			}
			if err := chk.Server(ctx, s); err != nil {
				failed = true
				fmt.Printf("  ✗ %s: %v\n", s.ID, err)
				continue
			}
			fmt.Printf("  ✓ %s: exit ip ok\n", s.ID)
			if *load > 0 {
				ok, total, err := chk.Load(ctx, s, *load)
				fmt.Printf("    load %d/%d %v\n", ok, total, err)
				if err != nil || ok != total {
					failed = true
				}
			}
		}
		if failed {
			die("verify failed")
		}
	default:
		die("unknown command %q", strings.Join(a, " "))
	}
}
