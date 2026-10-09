package deploy

import (
	"context"
	"fmt"
	"strings"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

type call struct {
	Server string
	Root   bool
	Cmd    string
}

type fakeRunner struct {
	calls []call
	fail  map[string]string // "server:substring" → error text
	out   map[string]string // substring → stdout
}

func (f *fakeRunner) Run(_ context.Context, s registry.Server, root bool, cmd string, _ []byte) ([]byte, error) {
	f.calls = append(f.calls, call{s.ID, root, cmd})
	for k, msg := range f.fail {
		p := strings.SplitN(k, ":", 2)
		if p[0] == s.ID && strings.Contains(cmd, p[1]) {
			return nil, fmt.Errorf("%s", msg)
		}
	}
	for k, o := range f.out {
		if strings.Contains(cmd, k) {
			return []byte(o), nil
		}
	}
	return nil, nil
}

func (f *fakeRunner) cmds(server string) []string {
	var out []string
	for _, c := range f.calls {
		if c.Server == server {
			out = append(out, c.Cmd)
		}
	}
	return out
}
