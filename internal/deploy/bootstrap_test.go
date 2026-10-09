package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

var kz = registry.Server{ID: "kz", Host: "192.0.2.10", Port: 443, SSH: registry.SSH{User: "vpn-deploy", Key: "~/.ssh/test"}}

func TestBootstrapRefusesBusy443(t *testing.T) {
	f := &fakeRunner{out: map[string]string{"ss -ltnpH": "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1))"}}
	err := Bootstrap(context.Background(), f, kz, []byte("#!/bin/bash"), "ssh-ed25519 AAAA test")
	if err == nil || !strings.Contains(err.Error(), "443 busy") {
		t.Fatalf("want 443 busy, got %v", err)
	}
}

func TestBootstrapSteps(t *testing.T) {
	f := &fakeRunner{out: map[string]string{"ss -ltnpH": ""}}
	if err := Bootstrap(context.Background(), f, kz, []byte("#!/bin/bash"), "ssh-ed25519 AAAA test"); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(f.cmds("kz"), "\n")
	for _, want := range []string{"useradd", "authorized_keys", "/etc/sudoers.d/vpn-deploy", "/usr/local/sbin/vpn-helper", "docker version", "/etc/vpn-xray/releases"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing step %q", want)
		}
	}
	for _, c := range f.calls {
		if !c.Root {
			t.Errorf("bootstrap must run as root: %s", c.Cmd)
		}
	}
}

func TestProbeTargetRejectsInvalidHostnameBeforeSSH(t *testing.T) {
	for _, domain := range []string{"", "example.org;id", "$(id)", "example.org/path", "EXAMPLE.org", "a b", "a\nb"} {
		f := &fakeRunner{}
		_, err := ProbeTarget(context.Background(), f, kz, domain)
		if err == nil || len(f.calls) != 0 {
			t.Errorf("invalid hostname reached SSH: %q", domain)
		}
	}
}
func TestProbeTargetValidHostname(t *testing.T) {
	f := &fakeRunner{out: map[string]string{"curl": "2 0 0.012"}}
	res, err := ProbeTarget(context.Background(), f, kz, "www.example-test.org")
	if err != nil || !res.TLS13 || !res.H2 || res.ConnectMS != 12 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestBootstrapAllowsOwnXray(t *testing.T) {
	f := &fakeRunner{out: map[string]string{"ss -ltnpH": "LISTEN 0 4096 *:443 *:* users:((\"xray\",pid=4242,fd=3))"}}
	if err := Bootstrap(context.Background(), f, kz, []byte("#!/bin/bash"), "ssh-ed25519 AAAA test"); err != nil {
		t.Fatalf("re-bootstrap over running vpn-xray refused: %v", err)
	}
}

func TestBootstrapChecksServerPort(t *testing.T) {
	s := kz
	s.Port = 9443
	f := &fakeRunner{out: map[string]string{"ss -ltnpH": ""}}
	if err := Bootstrap(context.Background(), f, s, []byte("#!/bin/bash"), "ssh-ed25519 AAAA test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.cmds("kz")[0], "sport = :9443") {
		t.Fatalf("checked wrong port: %s", f.cmds("kz")[0])
	}
}
