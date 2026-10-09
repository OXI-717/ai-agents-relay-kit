package users

import (
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func load(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAddUser(t *testing.T) {
	r := load(t)
	if err := Add(r, "dave", "Дейв"); err != nil {
		t.Fatal(err)
	}
	if errs := r.Validate(); len(errs) != 0 {
		t.Fatalf("invalid after add: %v", errs)
	}
	if r.Secrets.UUIDs["dave@kz"] == "" || r.Secrets.UUIDs["dave@am"] == "" {
		t.Fatal("uuids not created")
	}
	if err := Add(r, "dave", "x"); err == nil {
		t.Fatal("duplicate add allowed")
	}
}

func TestAddUserNeverReusesRevoked(t *testing.T) {
	r := load(t)
	_ = Add(r, "dave", "Дейв")
	for _, rv := range r.Secrets.RevokedUUIDs {
		for k, v := range r.Secrets.UUIDs {
			if v == rv {
				t.Fatalf("%s got revoked uuid", k)
			}
		}
	}
}

func TestFillKeepsExisting(t *testing.T) {
	r := load(t)
	before := r.Secrets.UUIDs["alice@kz"]
	delete(r.Secrets.UUIDs, "alice@am")
	added := Fill(r)
	if len(added) != 1 || added[0] != "alice@am" {
		t.Fatalf("added %v", added)
	}
	if r.Secrets.UUIDs["alice@kz"] != before {
		t.Fatal("existing uuid changed")
	}
}

func TestRevoke(t *testing.T) {
	r := load(t)
	kz := r.Secrets.UUIDs["alice@kz"]
	if err := Revoke(r, "alice"); err != nil {
		t.Fatal(err)
	}
	if r.Users[0].Status != "revoked" {
		t.Fatal("status")
	}
	if _, ok := r.Secrets.UUIDs["alice@kz"]; ok {
		t.Fatal("uuid still active")
	}
	if _, ok := r.Secrets.Users["alice"]; ok {
		t.Fatal("token kept")
	}
	found := false
	for _, v := range r.Secrets.RevokedUUIDs {
		found = found || v == kz
	}
	if !found {
		t.Fatal("not in revoked list")
	}
	if err := Revoke(r, "nobody"); err == nil {
		t.Fatal("unknown user revoked")
	}
}

func TestServerKeysNoOverwrite(t *testing.T) {
	r := load(t)
	if err := ServerKeys(r, "kz", false); err == nil {
		t.Fatal("overwrote existing keys without force")
	}
	if err := ServerKeys(r, "kz", true); err != nil {
		t.Fatal(err)
	}
	s, _ := r.ServerByID("kz")
	if s.Reality.PublicKey == "TESTPUBKZ" || r.Secrets.Servers["kz"].PrivateKey == "TESTPRIVKZ" {
		t.Fatal("keys not regenerated")
	}
}

func TestFillTokens(t *testing.T) {
	r := load(t)
	keep := r.Secrets.Users["alice"].Token
	delete(r.Secrets.Users, "bob")
	added, err := FillTokens(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != "bob" {
		t.Fatalf("added %v", added)
	}
	if r.Secrets.Users["alice"].Token != keep {
		t.Fatal("existing token changed")
	}
	if _, ok := r.Secrets.Users["carol"]; ok {
		t.Fatal("token issued to revoked user")
	}
}
