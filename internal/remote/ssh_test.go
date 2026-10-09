package remote

import (
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func TestRootTargetDefault(t *testing.T) {
	user, cmd := rootTarget(registry.Server{}, "ss -ltnpH 'sport = :443'")
	if user != "root" || cmd != "ss -ltnpH 'sport = :443'" {
		t.Fatalf("%s %q", user, cmd)
	}
}

func TestBootstrapIdentity(t *testing.T) {
	if got := bootstrapIdentity(registry.Server{}); got != expand("~/.ssh/id_rsa") {
		t.Fatalf("default %s", got)
	}
	s := registry.Server{SSH: registry.SSH{BootstrapKey: "/tmp/relay.key"}}
	if got := bootstrapIdentity(s); got != "/tmp/relay.key" {
		t.Fatalf("custom %s", got)
	}
}

func TestRootTargetViaSudo(t *testing.T) {
	s := registry.Server{SSH: registry.SSH{BootstrapUser: "yozh-dev-oxi"}}
	user, cmd := rootTarget(s, "echo 'a b' > /tmp/x && id")
	if user != "yozh-dev-oxi" {
		t.Fatalf("user %s", user)
	}
	want := `sudo -n sh -c 'echo '\''a b'\'' > /tmp/x && id'`
	if cmd != want {
		t.Fatalf("cmd\n got %s\nwant %s", cmd, want)
	}
}
