package deploy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func testReg(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var okVerify = VerifyFunc(func(context.Context, registry.Server) error { return nil })

func TestDeployHappyPath(t *testing.T) {
	f := &fakeRunner{}
	res := Servers(context.Background(), testReg(t), f, okVerify, "", StopOnError, "20260929T120000000000000Z")
	if len(res) != 3 || res[0].Err != nil || res[1].Err != nil {
		t.Fatalf("res %+v", res)
	}
	kz := strings.Join(f.cmds("kz"), "\n")
	for _, want := range []string{"vpn-helper install 20260929T120000000000000Z", "vpn-helper test 20260929T120000000000000Z", "vpn-helper activate 20260929T120000000000000Z", "vpn-helper prune"} {
		if !strings.Contains(kz, want) {
			t.Errorf("missing %q", want)
		}
	}
	if res[len(res)-1].Status != "never deployed" {
		t.Fatal("missing never deployed status")
	}
	if len(f.cmds("off")) != 0 {
		t.Fatal("disabled server touched")
	}
}

func TestDeployRollsBackOnVerifyFail(t *testing.T) {
	f := &fakeRunner{}
	bad := VerifyFunc(func(_ context.Context, s registry.Server) error {
		if s.ID == "kz" {
			return errors.New("exit ip mismatch")
		}
		return nil
	})
	res := Servers(context.Background(), testReg(t), f, bad, "", StopOnError, "20260929T120000000000000Z")
	if len(res) != 1 || !res[0].RolledBack || res[0].Err == nil {
		t.Fatalf("res %+v", res)
	}
	if !strings.Contains(strings.Join(f.cmds("kz"), "\n"), "vpn-helper rollback") {
		t.Fatal("no rollback")
	}
}

func TestDeployStopsAtFirstFailure(t *testing.T) {
	f := &fakeRunner{fail: map[string]string{"kz:vpn-helper test": "config invalid"}}
	res := Servers(context.Background(), testReg(t), f, okVerify, "", StopOnError, "20260929T120000000000000Z")
	if len(res) != 1 || res[0].Err == nil {
		t.Fatalf("res %+v", res)
	}
	if strings.Contains(strings.Join(f.cmds("kz"), "\n"), "activate") {
		t.Fatal("activated after failed test")
	}
	if len(f.cmds("am")) != 0 {
		t.Fatal("continued to next server")
	}
}

func TestRevokeContinuesOnFailure(t *testing.T) {
	f := &fakeRunner{fail: map[string]string{"kz:vpn-helper install": "ssh: connect timeout"}}
	res := Servers(context.Background(), testReg(t), f, okVerify, "", Revoke, "20260929T120000000000000Z")
	if len(res) != 3 || res[0].Err == nil || res[1].Err != nil {
		t.Fatalf("res %+v", res)
	}
}

func TestDeployOnlyOne(t *testing.T) {
	f := &fakeRunner{}
	res := Servers(context.Background(), testReg(t), f, okVerify, "am", StopOnError, "20260929T120000000000000Z")
	if len(res) != 1 || res[0].Server != "am" || len(f.cmds("kz")) != 0 {
		t.Fatalf("res %+v", res)
	}
}

func TestRevokeSealsOrStopsWithoutRollback(t *testing.T) {
	for _, stage := range []string{"success", "install", "test", "build", "activate", "verify", "seal"} {
		t.Run(stage, func(t *testing.T) {
			f := &fakeRunner{fail: map[string]string{}}
			if stage == "install" || stage == "test" || stage == "activate" || stage == "seal" {
				f.fail["kz:vpn-helper "+stage] = "failure"
			}
			verify := okVerify
			if stage == "verify" {
				verify = VerifyFunc(func(context.Context, registry.Server) error { return errors.New("verify failed") })
			}
			// Mode 1 was Revoke; it must now implement fail-closed revoke.
			r := testReg(t)
			if stage == "build" {
				delete(r.Secrets.Servers, "kz")
			}
			res := Servers(context.Background(), r, f, verify, "kz", Mode(1), helperID)
			cmds := strings.Join(f.cmds("kz"), "\n")
			if strings.Contains(cmds, "rollback") {
				t.Fatal("revoke rolled back")
			}
			if stage == "success" {
				if !strings.Contains(cmds, "vpn-helper seal") || res[0].Err != nil {
					t.Fatal("revoke not sealed")
				}
			} else {
				if res[0].Err == nil || res[0].RolledBack || !strings.Contains(cmds, "vpn-helper stop") {
					t.Fatal("failure not stopped and reported")
				}
			}
		})
	}
}

func TestDisabledServersStoppedAndNeverDeployedReported(t *testing.T) {
	for _, mode := range []Mode{StopOnError, Revoke} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			r := testReg(t)
			r.Servers[0].Enabled = false
			f := &fakeRunner{fail: map[string]string{"kz:vpn-helper stop": "offline"}}
			res := Servers(context.Background(), r, f, okVerify, "", mode, helperID)
			if len(res) != 3 {
				t.Fatalf("missing node results: %+v", res)
			}
			if !strings.Contains(strings.Join(f.cmds("kz"), "\n"), "vpn-helper stop") {
				t.Fatal("disabled node not stopped")
			}
			if res[0].Err == nil {
				t.Fatal("stop error not reported")
			}
			if len(f.cmds("am")) == 0 {
				t.Fatal("stop warning prevented next deployment")
			}
			if res[len(res)-1].Status != "never deployed" {
				t.Fatal("missing never deployed status")
			}
			if len(f.cmds("off")) != 0 {
				t.Fatal("never deployed node touched")
			}
		})
	}
}

func TestDeployExitsBeforeRelay(t *testing.T) {
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
	var order []string
	check := VerifyFunc(func(_ context.Context, s registry.Server) error { order = append(order, s.ID); return nil })
	res := Servers(context.Background(), r, &fakeRunner{}, check, "", StopOnError, "20260929T120000000000000Z")
	// Direct profiles verified at each exit step; relay pairs re-verified once
	// the relay they enter through is active.
	if len(res) != 4 || strings.Join(order, ",") != "kz,am,tw,kz,am" {
		t.Fatalf("wrong deploy order: %v %+v", order, res)
	}
	res = Servers(context.Background(), r, &fakeRunner{}, check, "tw", StopOnError, "20260929T120000000000000Z")
	if len(res) != 1 || res[0].Server != "tw" || res[0].Err != nil {
		t.Fatalf("relay filter: %+v", res)
	}
}
