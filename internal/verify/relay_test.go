package verify

import (
	"context"
	"github.com/OXI-717/ai-agents-relay-kit/internal/build"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRelayChecksEveryPairAgainstExit(t *testing.T) {
	r, err := registry.Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	relay := r.Servers[0]
	relay.ID = "tr"
	relay.Kind = "relay"
	relay.Exits = []string{"am", "kz"}
	r.Servers = append(r.Servers, relay)
	r.Users[1].Entries = []string{"tr"}
	for _, k := range []string{"alice@tr/am", "alice@tr/kz", "bob@tr/am", "bob@tr/kz"} {
		r.Secrets.UUIDs[k] = "synthetic-" + k
	}
	c := New(r, "")
	var checked []string
	c.startTunnel = func(_ context.Context, p build.Profile) (*http.Client, func(), error) {
		checked = append(checked, p.Key)
		h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(p.Exit.Host)) }))
		hc := h.Client()
		hc.Transport = redirectTransport{url: h.URL, base: hc.Transport}
		return hc, h.Close, nil
	}
	if err := c.Server(context.Background(), relay); err != nil {
		t.Fatal(err)
	}
	if len(checked) != 4 {
		t.Fatalf("checked only %v", checked)
	}
	c.startTunnel = func(_ context.Context, p build.Profile) (*http.Client, func(), error) {
		h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(relay.Host)) }))
		hc := h.Client()
		hc.Transport = redirectTransport{url: h.URL, base: hc.Transport}
		return hc, h.Close, nil
	}
	if err := c.Server(context.Background(), relay); err == nil {
		t.Fatal("relay IP must not pass as exit IP")
	}
}

// An exit reached only through relay pairs (no direct users) is still verified:
// the tunnel enters via the relay, the expected IP stays the exit's.
func TestExitUsedOnlyViaRelay(t *testing.T) {
	r, err := registry.Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	relay := r.Servers[0]
	relay.ID = "tr"
	relay.Kind = "relay"
	relay.Exits = []string{"am"}
	r.Servers = append(r.Servers, relay)
	r.Users[0].Entries = []string{"tr"}
	r.Users[1].Entries = []string{"tr"}
	for _, k := range []string{"alice@tr/am", "bob@tr/am"} {
		r.Secrets.UUIDs[k] = "synthetic-" + k
	}
	c := New(r, "")
	var checked []string
	c.startTunnel = func(_ context.Context, p build.Profile) (*http.Client, func(), error) {
		checked = append(checked, p.Key)
		h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(p.Exit.Host)) }))
		hc := h.Client()
		hc.Transport = redirectTransport{url: h.URL, base: hc.Transport}
		return hc, h.Close, nil
	}
	am, _ := r.ServerByID("am")
	if err := c.Server(context.Background(), am); err != nil {
		t.Fatalf("exit via relay must verify: %v", err)
	}
	if len(checked) != 2 || checked[0] != "alice@tr/am" || checked[1] != "bob@tr/am" {
		t.Fatalf("checked %v, want relay pairs", checked)
	}
}

type redirectTransport struct {
	url  string
	base http.RoundTripper
}

func (r redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	n, _ := http.NewRequestWithContext(req.Context(), req.Method, r.url+req.URL.RequestURI(), nil)
	return r.base.RoundTrip(n)
}

func TestLoadReportsPartialFailure(t *testing.T) {
	r, err := registry.Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	c := New(r, "")
	c.startTunnel = func(_ context.Context, _ build.Profile) (*http.Client, func(), error) {
		h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/__down" {
				w.Write(make([]byte, 20000000))
				return
			}
			w.WriteHeader(503)
		}))
		hc := h.Client()
		hc.Transport = redirectTransport{url: h.URL, base: hc.Transport}
		return hc, h.Close, nil
	}
	s, _ := r.ServerByID("kz")
	n, total, err := c.Load(context.Background(), s, 2)
	if err == nil || n == total {
		t.Fatalf("partial failures accepted: %d/%d %v", n, total, err)
	}
}
