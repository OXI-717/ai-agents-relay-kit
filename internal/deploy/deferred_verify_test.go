package deploy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

// stagedVerifier fails an exit's relay pairs while the relay they enter
// through has not been activated yet, reproducing the review scenario.
type stagedVerifier struct {
	runner *fakeRunner
	relay  string
	bad    map[string]bool // exits that keep failing even after relay is up
	calls  []string
}

func (v *stagedVerifier) relayUp() bool {
	for _, c := range v.runner.cmds(v.relay) {
		if strings.Contains(c, "vpn-helper activate") {
			return true
		}
	}
	return false
}

func (v *stagedVerifier) Server(_ context.Context, s registry.Server) error {
	v.calls = append(v.calls, "full:"+s.ID)
	if s.Kind == "exit" && !v.relayUp() {
		return fmt.Errorf("alice@%s/%s: relay not deployed yet", v.relay, s.ID)
	}
	if v.bad[s.ID] {
		return fmt.Errorf("alice@%s/%s: wrong exit ip", v.relay, s.ID)
	}
	return nil
}

func (v *stagedVerifier) ServerDirect(_ context.Context, s registry.Server) error {
	v.calls = append(v.calls, "direct:"+s.ID)
	return nil
}

// An exit whose relay pairs depend on a relay deployed later in the same run
// must not be rolled back: direct profiles are checked at the exit step and
// the relay pairs once the relay is active.
func TestDeployExitVerifyWaitsForRelay(t *testing.T) {
	r := relayReg(t)
	f := &fakeRunner{}
	v := &stagedVerifier{runner: f, relay: "tw"}
	res := Servers(context.Background(), r, f, v, "", StopOnError, helperID)
	if len(res) != 4 {
		t.Fatalf("results %+v", res)
	}
	for _, x := range res {
		if x.Err != nil || x.RolledBack {
			t.Fatalf("deploy must not roll back a healthy exit: %+v", x)
		}
		if x.Server == "kz" && x.Status != "active, verify ok" {
			t.Fatalf("kz must be verified after relay: %+v", x)
		}
	}
	var directAt, activateRelay, fullAt = -1, -1, -1
	for i, c := range v.calls {
		if c == "direct:kz" {
			directAt = i
		}
		if c == "full:kz" {
			fullAt = i
		}
	}
	for i, c := range f.cmds("tw") {
		if strings.Contains(c, "vpn-helper activate") {
			activateRelay = i
		}
	}
	if directAt < 0 || fullAt < 0 || activateRelay < 0 {
		t.Fatalf("expected direct+full verify and relay activation: calls %v cmds %v", v.calls, f.cmds("tw"))
	}
	if fullAt <= directAt {
		t.Fatalf("relay-pair verify ran before relay deploy: %v", v.calls)
	}
}

// An exit with no direct users is not verified at its own step at all: it is
// marked deferred and verified through the relay pairs once the relay is up.
func TestDeployRelayOnlyExitDeferred(t *testing.T) {
	r := relayReg(t)
	// alice enters only via tw: am has no direct users at all, kz keeps bob.
	r.Users[0].Entries = []string{"tw"}
	f := &fakeRunner{}
	v := &stagedVerifier{runner: f, relay: "tw"}
	res := Servers(context.Background(), r, f, v, "", StopOnError, helperID)
	if len(res) != 4 {
		t.Fatalf("results %+v", res)
	}
	for _, x := range res {
		if x.Err != nil {
			t.Fatalf("unexpected error: %+v", x)
		}
		if (x.Server == "kz" || x.Server == "am") && x.Status != "active, verify ok" {
			t.Fatalf("exit not verified after relay: %+v", x)
		}
	}
	var directAm, directKz, fullAm bool
	for _, c := range v.calls {
		directAm = directAm || c == "direct:am"
		directKz = directKz || c == "direct:kz"
		fullAm = fullAm || c == "full:am"
	}
	if directAm || !directKz || !fullAm {
		t.Fatalf("relay-only exit must skip direct verify, mixed exit must run it: %v", v.calls)
	}
}

// When the deferred relay-pair verify fails, the relay is rolled back as usual
// and the error names the exit that could not be confirmed.
func TestDeployRelayRolledBackWhenExitVerifyFails(t *testing.T) {
	r := relayReg(t)
	f := &fakeRunner{}
	v := &stagedVerifier{runner: f, relay: "tw", bad: map[string]bool{"kz": true}}
	res := Servers(context.Background(), r, f, v, "", StopOnError, helperID)
	var relay *Result
	for i := range res {
		if res[i].Server == "tw" {
			relay = &res[i]
		}
	}
	if relay == nil || relay.Err == nil || !relay.RolledBack {
		t.Fatalf("relay must roll back when exit verify fails: %+v", res)
	}
	if !strings.Contains(relay.Err.Error(), "kz") {
		t.Fatalf("error must name the exit: %v", relay.Err)
	}
	if !strings.Contains(strings.Join(f.cmds("tw"), "\n"), "vpn-helper rollback") {
		t.Fatal("relay rollback not invoked")
	}
}
