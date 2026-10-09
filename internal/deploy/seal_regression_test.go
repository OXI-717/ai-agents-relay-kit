package deploy

import (
	"context"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"os"
	"strings"
	"testing"
)

type reviewSealGapRunner struct {
	realHelperRunner
	old string
}

func (h reviewSealGapRunner) Run(ctx context.Context, s registry.Server, root bool, cmd string, input []byte) ([]byte, error) {
	if strings.Contains(cmd, "vpn-helper seal") {
		if out, e := h.run("", "activate", h.old); e != nil {
			return []byte(out), e
		}
	}
	return h.realHelperRunner.Run(ctx, s, root, cmd, input)
}
func TestThirdReviewSealGap(t *testing.T) {
	h := newHelper(t)
	old := "20260929T110000000000000Z"
	if o, e := h.run("OLD-USER", "install", old, helperImage); e != nil {
		t.Fatal(o, e)
	}
	r := testReg(t)
	r.Pins.ServerImage = helperImage
	verified := false
	check := VerifyFunc(func(context.Context, registry.Server) error {
		b, e := os.ReadFile(h.base + "/current/config.json")
		if e != nil || strings.Contains(string(b), "OLD-USER") {
			t.Fatal("clean release not active during verify")
		}
		verified = true
		return nil
	})
	res := Servers(context.Background(), r, reviewSealGapRunner{realHelperRunner{h}, old}, check, "kz", Revoke, helperID)
	if !verified || len(res) != 1 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "seal failed") {
		t.Fatalf("stale release confirmed: %+v", res)
	}
	if _, err := os.Lstat(h.base + "/current"); !os.IsNotExist(err) {
		t.Fatal("fail-closed stop did not remove current")
	}
	if _, err := os.Stat(h.base + "/barrier"); !os.IsNotExist(err) {
		t.Fatal("stale release sealed")
	}
}

func TestHelperSealChecksContainer(t *testing.T) {
	for _, state := range []string{"wrong-label", "wrong-mount", "stopped", "absent"} {
		t.Run(state, func(t *testing.T) {
			h := newHelper(t)
			if out, err := h.run("{}", "install", helperID, helperImage); err != nil {
				t.Fatal(out, err)
			}
			if out, err := h.run("", "activate", helperID); err != nil {
				t.Fatal(out, err)
			}
			value := "true|" + helperID + "|" + h.base + "/releases/" + helperID
			switch state {
			case "wrong-label":
				value = "true|old|" + h.base + "/releases/" + helperID
			case "wrong-mount":
				value = "true|" + helperID + "|/wrong"
			case "stopped":
				value = "false|" + helperID + "|" + h.base + "/releases/" + helperID
			case "absent":
				value = ""
			}
			if err := os.WriteFile(h.base+"/container", []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := h.run("", "seal", helperID); err == nil {
				t.Fatal("invalid container sealed")
			}
			if _, err := os.Stat(h.base + "/barrier"); !os.IsNotExist(err) {
				t.Fatal("barrier written")
			}
		})
	}
}
