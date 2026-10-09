package deploy

import (
	"context"
	"errors"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"os"
	"strings"
	"testing"
)

type reviewEarlyRunner struct {
	realHelperRunner
	fail string
}

func (h reviewEarlyRunner) Run(ctx context.Context, s registry.Server, root bool, cmd string, input []byte) ([]byte, error) {
	if strings.Contains(cmd, "vpn-helper "+h.fail+" ") {
		return nil, errors.New("synthetic reachable helper failure")
	}
	return h.realHelperRunner.Run(ctx, s, root, cmd, input)
}
func TestRevokeEarlyFailureStopsOldRelease(t *testing.T) {
	for _, stage := range []string{"install", "test"} {
		t.Run(stage, func(t *testing.T) {
			h := newHelper(t)
			h.run(`{"clients":["REVOKED-USER"]}`, "install", "20260929T110000000000000Z", helperImage)
			h.run("", "activate", "20260929T110000000000000Z")
			r := testReg(t)
			r.Pins.ServerImage = helperImage
			res := Servers(context.Background(), r, reviewEarlyRunner{realHelperRunner{h}, stage}, okVerify, "kz", Revoke, helperID)
			b, _ := os.ReadFile(h.base + "/docker.log")
			cfg, _ := os.ReadFile(h.base + "/current/config.json")
			if res[0].Err == nil || strings.Contains(string(cfg), "REVOKED-USER") {
				t.Fatal("old release retained")
			}
			if strings.Count(string(b), "rm -f vpn-xray") != 2 {
				t.Fatal("stop was not attempted")
			}
			t.Logf("%s failure: old release stopped", stage)
		})
	}
}
func TestIndependentDisabled(t *testing.T) {
	r := testReg(t)
	r.Servers[0].Enabled = false
	f := &fakeRunner{}
	res := Servers(context.Background(), r, f, okVerify, "kz", Revoke, helperID)
	if res[0].Err != nil || len(f.cmds("kz")) != 1 || !strings.HasSuffix(f.cmds("kz")[0], " stop") {
		t.Fatal(res)
	}
	t.Log("disabled deployed node: stop attempted and successful")
}
func TestIndependentStopFailureReported(t *testing.T) {
	r := testReg(t)
	f := &fakeRunner{fail: map[string]string{"kz:vpn-helper activate": "synthetic activate failure", "kz:vpn-helper stop": "synthetic stop failure"}}
	res := Servers(context.Background(), r, f, okVerify, "", Revoke, helperID)
	if len(res) != 3 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "STOP FAILED") || len(f.cmds("am")) == 0 {
		t.Fatal(res)
	}
	t.Log("stop failure is unconfirmed; next server attempted")
}
