package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func relayReg(t *testing.T) *registry.Registry {
	t.Helper()
	r := testReg(t)
	relay := r.Servers[0]
	relay.ID = "tw"
	relay.Kind = "relay"
	relay.Exits = []string{"am", "kz"}
	r.Servers = append([]registry.Server{relay}, r.Servers...)
	r.Secrets.Servers["tw"] = r.Secrets.Servers["kz"]
	for _, k := range []string{"alice@tw/am", "alice@tw/kz", "svc:tw>am", "svc:tw>kz"} {
		r.Secrets.UUIDs[k] = "synthetic-" + k
	}
	return r
}

type relayRunner struct {
	fakeRunner
	t     *testing.T
	image string
}

func (f *relayRunner) Run(ctx context.Context, s registry.Server, root bool, cmd string, input []byte) ([]byte, error) {
	if strings.Contains(cmd, "vpn-helper install ") {
		if cmd != "sudo /usr/local/sbin/vpn-helper install "+helperID+" "+f.image {
			f.t.Errorf("wrong install command: %s", cmd)
		}
		var config map[string]any
		if json.Unmarshal(input, &config) != nil || config["inbounds"] == nil {
			f.t.Error("install must receive raw config JSON, not tar")
		}
	}
	return f.fakeRunner.Run(ctx, s, root, cmd, input)
}

func TestRelayRevokeSealsOrStopsWithoutRollback(t *testing.T) {
	for _, stage := range []string{"success", "install", "test", "activate", "verify", "seal", "build"} {
		t.Run(stage, func(t *testing.T) {
			r := relayReg(t)
			f := &relayRunner{t: t, image: r.Pins.ServerImage, fakeRunner: fakeRunner{fail: map[string]string{}}}
			check := okVerify
			switch stage {
			case "verify":
				check = VerifyFunc(func(context.Context, registry.Server) error { return errors.New("bad exit IP") })
			case "build":
				delete(r.Secrets.UUIDs, "svc:tw>am")
			case "success":
			default:
				f.fail["tw:vpn-helper "+stage] = "failure"
			}
			results := Servers(context.Background(), r, f, check, "tw", Revoke, helperID)
			if len(results) != 1 {
				t.Fatalf("results %+v", results)
			}
			cmds := strings.Join(f.cmds("tw"), "\n")
			if strings.Contains(cmds, "rollback") || results[0].RolledBack {
				t.Fatal("relay revoke rolled back")
			}
			if stage == "success" {
				if results[0].Err != nil || !strings.Contains(cmds, "vpn-helper seal "+helperID) {
					t.Fatalf("relay not sealed: %+v", results)
				}
			} else if results[0].Err == nil || !strings.Contains(cmds, "vpn-helper stop") {
				t.Fatalf("relay failure not stopped: %+v", results)
			}
		})
	}
}

func TestDisabledRelayStoppedInBothModes(t *testing.T) {
	for _, mode := range []Mode{StopOnError, Revoke} {
		r := relayReg(t)
		r.Servers[0].Enabled = false
		f := &fakeRunner{}
		results := Servers(context.Background(), r, f, okVerify, "tw", mode, helperID)
		if len(results) != 1 || results[0].Err != nil || results[0].Status != "stopped" {
			t.Fatalf("results %+v", results)
		}
		cmds := f.cmds("tw")
		if len(cmds) != 1 || cmds[0] != "sudo /usr/local/sbin/vpn-helper stop" {
			t.Fatalf("disabled relay commands: %v", cmds)
		}
	}
}

func TestExitRevokeFailureStillReachesRelay(t *testing.T) {
	r := relayReg(t)
	f := &fakeRunner{fail: map[string]string{"kz:vpn-helper install": "offline"}}
	results := Servers(context.Background(), r, f, okVerify, "", Revoke, helperID)
	if len(results) != 4 || results[0].Server != "kz" || results[0].Err == nil {
		t.Fatalf("results %+v", results)
	}
	if !strings.Contains(strings.Join(f.cmds("tw"), "\n"), "vpn-helper seal "+helperID) {
		t.Fatal("exit failure prevented relay revocation")
	}
}
