package users

import (
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"testing"
)

func TestFillRelayAndRevoke(t *testing.T) {
	r, err := registry.Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	relay := r.Servers[0]
	relay.ID = "tw"
	relay.Kind = "relay"
	relay.Exits = []string{"am", "kz"}
	r.Servers = append(r.Servers, relay)
	original := r.Secrets.UUIDs["alice@kz"]
	added := Fill(r)
	if len(added) != 4 {
		t.Fatalf("want two user pairs and two services, got %v", added)
	}
	for _, k := range []string{"alice@tw/am", "alice@tw/kz", "svc:tw>am", "svc:tw>kz"} {
		if r.Secrets.UUIDs[k] == "" {
			t.Errorf("missing %s", k)
		}
	}
	if r.Secrets.UUIDs["alice@kz"] != original || len(Fill(r)) != 0 {
		t.Fatal("fill changed existing IDs")
	}
	if err := Revoke(r, "alice"); err != nil {
		t.Fatal(err)
	}
	if r.Secrets.UUIDs["alice@tw/am"] != "" || r.Secrets.UUIDs["svc:tw>am"] == "" {
		t.Fatal("revoke must preserve service IDs only")
	}
}
