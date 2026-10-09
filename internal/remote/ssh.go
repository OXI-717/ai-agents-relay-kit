// Package remote runs commands on servers over the system ssh with pinned host keys.
package remote

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

type Runner interface {
	Run(ctx context.Context, s registry.Server, asRoot bool, cmd string, stdin []byte) ([]byte, error)
}

type SSH struct{ KnownHosts string }

func NewSSH(knownHosts string) *SSH { return &SSH{KnownHosts: knownHosts} }

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return h + p[1:]
	}
	return p
}

func (x *SSH) Run(ctx context.Context, s registry.Server, asRoot bool, cmd string, stdin []byte) ([]byte, error) {
	user, key := s.SSH.User, expand(s.SSH.Key)
	if asRoot {
		user, cmd = rootTarget(s, cmd)
		key = bootstrapIdentity(s)
	}
	c := exec.CommandContext(ctx, "ssh", "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+x.KnownHosts,
		user+"@"+s.Host, cmd)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s: %s: %v: %s", s.ID, firstWord(cmd), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func bootstrapIdentity(s registry.Server) string {
	if s.SSH.BootstrapKey != "" {
		return expand(s.SSH.BootstrapKey)
	}
	return expand("~/.ssh/id_rsa")
}

// rootTarget picks who runs a root-level command: root itself, or the server's
// bootstrap user through non-interactive sudo.
func rootTarget(s registry.Server, cmd string) (string, string) {
	if s.SSH.BootstrapUser == "" || s.SSH.BootstrapUser == "root" {
		return "root", cmd
	}
	return s.SSH.BootstrapUser, "sudo -n sh -c '" + strings.ReplaceAll(cmd, "'", `'\''`) + "'"
}

func firstWord(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) > 2 {
		return strings.Join(f[:3], " ")
	}
	return cmd
}
