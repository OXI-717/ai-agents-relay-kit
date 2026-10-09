package build

import (
	"github.com/OXI-717/ai-agents-relay-kit/internal/gen"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRelayPinnedXray(t *testing.T) {
	binary, err := filepath.Abs("../../bin/xray")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skip("pinned bin/xray not installed")
	}
	r := relayRegistry(t)
	for i := range r.Servers {
		priv, pub, err := gen.RealityKeys()
		if err != nil {
			t.Fatal(err)
		}
		s := &r.Servers[i]
		s.Reality.PublicKey = pub
		sec := r.Secrets.Servers[s.ID]
		sec.PrivateKey = priv
		r.Secrets.Servers[s.ID] = sec
	}
	check := func(name string, b []byte) {
		t.Helper()
		path := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(binary, "run", "-test", "-c", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", name, err, out)
		}
	}
	for _, s := range r.Servers {
		if !s.Enabled {
			continue
		}
		b, err := ServerConfig(r, s)
		if err != nil {
			t.Fatal(err)
		}
		check("server-"+s.ID, b)
	}
	ps, err := Profiles(r, r.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		b, err := ClientConfig(r, p, 10808, registry.RoutingProfile{})
		if err != nil {
			t.Fatal(err)
		}
		check("client", b)
	}
}
