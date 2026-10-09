package build

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

var update = flag.Bool("update", false, "rewrite golden files")

func load(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := "../../testdata/golden/" + name
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s differs from golden; rerun with -update and review diff\n--- got\n%s", name, got)
	}
}

func TestServerConfigGolden(t *testing.T) {
	r := load(t)
	s, _ := r.ServerByID("kz")
	b, err := ServerConfig(r, s)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "server-kz.json", b)
}

func TestServerConfigSkipsRevoked(t *testing.T) {
	r := load(t)
	s, _ := r.ServerByID("kz")
	b, _ := ServerConfig(r, s)
	if strings.Contains(string(b), "carol@") || strings.Contains(string(b), r.Secrets.RevokedUUIDs[0]) {
		t.Fatal("revoked user in server config")
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	clients := cfg["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 2 { // alice@kz, bob@kz
		t.Fatalf("clients %d", len(clients))
	}
}

func TestServerConfigMissingUUID(t *testing.T) {
	r := load(t)
	delete(r.Secrets.UUIDs, "bob@kz")
	s, _ := r.ServerByID("kz")
	if _, err := ServerConfig(r, s); err == nil || !strings.Contains(err.Error(), "bob@kz") {
		t.Fatalf("want missing uuid error, got %v", err)
	}
}
