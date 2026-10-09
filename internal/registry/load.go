package registry

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/OXI-717/ai-agents-relay-kit/internal/sops"
)

const (
	secretsSops  = "secrets.sops.yaml"
	secretsPlain = "secrets.plain.yaml" // только testdata
)

func readYAML(dir, name string, into any) error {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	return nil
}

func Load(dir string) (*Registry, error) {
	r := &Registry{Dir: dir}
	var s struct {
		Servers []Server `yaml:"servers"`
	}
	var u struct {
		Users []User `yaml:"users"`
	}
	var e struct {
		External []External `yaml:"external"`
	}
	var ro struct {
		Routing   []RoutingProfile `yaml:"routing"`
		Transport Transport        `yaml:"transport"`
	}
	var p struct {
		Pins Pins `yaml:"pins"`
	}
	var c struct {
		Cloudflare Cloudflare `yaml:"cloudflare"`
	}
	for name, into := range map[string]any{
		"servers.yaml": &s, "users.yaml": &u, "external.yaml": &e,
		"routing.yaml": &ro, "pins.yaml": &p, "cloudflare.yaml": &c,
	} {
		if err := readYAML(dir, name, into); err != nil {
			return nil, err
		}
	}
	r.Servers, r.Users, r.External = s.Servers, u.Users, e.External
	r.Routing, r.Transport, r.Pins, r.Cloudflare = ro.Routing, ro.Transport, p.Pins, c.Cloudflare
	sec, err := loadSecrets(dir)
	if err != nil {
		return nil, err
	}
	r.Secrets = sec
	return r, nil
}

func loadSecrets(dir string) (Secrets, error) {
	var sec Secrets
	var raw []byte
	plain := filepath.Join(dir, secretsPlain)
	if b, err := os.ReadFile(plain); err == nil {
		raw = b
	} else if errors.Is(err, os.ErrNotExist) {
		b, err := sops.Decrypt(filepath.Join(dir, secretsSops))
		if err != nil {
			return sec, err
		}
		raw = b
	} else {
		return sec, err
	}
	if err := yaml.Unmarshal(raw, &sec); err != nil {
		return sec, fmt.Errorf("parse secrets: %w", err)
	}
	if sec.Servers == nil {
		sec.Servers = map[string]ServerSecrets{}
	}
	if sec.Users == nil {
		sec.Users = map[string]UserSecrets{}
	}
	if sec.UUIDs == nil {
		sec.UUIDs = map[string]string{}
	}
	if sec.External == nil {
		sec.External = map[string]string{}
	}
	return sec, nil
}

func SaveSecrets(dir string, sec Secrets) error {
	b, err := yaml.Marshal(sec)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, secretsPlain)); err == nil {
		return os.WriteFile(filepath.Join(dir, secretsPlain), b, 0o600)
	}
	return sops.Encrypt(b, filepath.Join(dir, secretsSops))
}

// SaveUsers rewrites users.yaml (used by user add/revoke).
func SaveUsers(dir string, users []User) error {
	b, err := yaml.Marshal(struct {
		Users []User `yaml:"users"`
	}{users})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "users.yaml"), b, 0o644)
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func SaveServers(dir string, servers []Server) error {
	b, err := yaml.Marshal(struct {
		Servers []Server `yaml:"servers"`
	}{servers})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "servers.yaml"), b, 0o644)
}

func SaveExternal(dir string, external []External) error {
	b, err := yaml.Marshal(struct {
		External []External `yaml:"external"`
	}{external})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "external.yaml"), b, 0o644)
}
