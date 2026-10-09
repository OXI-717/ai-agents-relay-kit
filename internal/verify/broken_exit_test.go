package verify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/build"
	"github.com/OXI-717/ai-agents-relay-kit/internal/deploy"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/users"
)

type failureRunner struct {
	active  map[string]bool
	stopped map[string]bool
	calls   []string
}

func (r *failureRunner) Run(_ context.Context, s registry.Server, _ bool, cmd string, _ []byte) ([]byte, error) {
	r.calls = append(r.calls, s.ID+": "+cmd)
	if strings.Contains(cmd, " activate ") {
		r.active[s.ID] = true
		r.stopped[s.ID] = false
	}
	if strings.HasSuffix(cmd, " rollback") || strings.HasSuffix(cmd, " stop") {
		r.active[s.ID] = false
	}
	if strings.HasSuffix(cmd, " stop") {
		r.stopped[s.ID] = true
	}
	return nil, nil
}

// An exit verified only through a new relay fails the deferred check: deploy
// must roll back both the relay and the unconfirmed exit; revoke must stop
// both fail-closed. The broken release must not stay active.
func TestBrokenDeferredExitRecovery(t *testing.T) {
	for _, mode := range []deploy.Mode{deploy.StopOnError, deploy.Revoke} {
		name := map[deploy.Mode]string{deploy.StopOnError: "deploy", deploy.Revoke: "revoke"}[mode]
		t.Run(name, func(t *testing.T) {
			r, err := registry.Load("../../testdata/registry")
			if err != nil {
				t.Fatal(err)
			}
			tw := r.Servers[0]
			tw.ID = "tw"
			tw.Kind = "relay"
			tw.Exits = []string{"kz", "am"}
			r.Servers = append(r.Servers, tw)
			r.Secrets.Servers["tw"] = r.Secrets.Servers["kz"]
			for i := range r.Users {
				r.Users[i].Entries = []string{"tw"}
			}
			users.Fill(r)
			run := &failureRunner{active: map[string]bool{}, stopped: map[string]bool{}}
			c := New(r, "")
			c.startTunnel = func(_ context.Context, p build.Profile) (*http.Client, func(), error) {
				// The relay is healthy; the newly activated kz release
				// returns the wrong egress IP.
				if run.stopped[p.Exit.ID] || run.stopped[p.Server.ID] {
					return nil, nil, fmt.Errorf("node stopped")
				}
				ip := p.Exit.Host
				if p.Exit.ID == "kz" && run.active["kz"] {
					ip = "192.0.2.99"
				}
				h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(ip)) }))
				hc := h.Client()
				hc.Transport = redirectTransport{url: h.URL, base: hc.Transport}
				return hc, h.Close, nil
			}
			result := deploy.Servers(context.Background(), r, run, c, "", mode, "20260929T120000000000000Z")
			for _, v := range result {
				t.Logf("server=%s status=%s err=%v rolledBack=%v", v.Server, v.Status, v.Err, v.RolledBack)
			}
			for _, cmd := range run.calls {
				t.Log(cmd)
			}
			if run.active["kz"] {
				t.Fatal("broken exit remains active: no rollback in deploy / no fail-closed stop in revoke")
			}
		})
	}
}
