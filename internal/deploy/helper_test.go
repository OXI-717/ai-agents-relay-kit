package deploy

import (
	"context"
	"errors"
	"fmt"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const helperID = "20260929T120000000000000Z"

var helperImage = "ghcr.io/xtls/xray-core@sha256:" + strings.Repeat("a", 64)

type helperFixture struct{ base, script, bin string }

func newHelper(t *testing.T) helperFixture {
	t.Helper()
	d := t.TempDir()
	h := helperFixture{filepath.Join(d, "base"), filepath.Join(d, "helper.sh"), filepath.Join(d, "bin")}
	b, err := os.ReadFile("../../deploy/vpn-helper.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Isolate the legacy script too, so a regression can never touch /etc.
	b = []byte(strings.ReplaceAll(string(b), "BASE=/etc/vpn-xray", `BASE=${VPN_HELPER_BASE:?}`))
	if err = os.WriteFile(h.script, b, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(h.bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(h.bin, "docker"), []byte(`#!/bin/sh
[ -n "${VPN_HELPER_SLOW:-}" ] && sleep "$VPN_HELPER_SLOW"
printf '%s\n' "$*" >> "$VPN_HELPER_BASE/docker.log"
case "$1" in
 inspect) cat "$VPN_HELPER_BASE/container" ;;
 rm) rm -f "$VPN_HELPER_BASE/container" ;;
 run)
  label= mount= detached=
  while [ "$#" -gt 0 ]; do
   case "$1" in
    -d) detached=yes ;;
    --label) shift; label=${1#vpn.release=} ;;
    -v) shift; mount=${1%:/etc/xray:ro} ;;
   esac
   shift
  done
  if [ "$detached" = yes ]; then printf 'true|%s|%s' "$label" "$mount" > "$VPN_HELPER_BASE/container"; fi
  ;;
esac
`), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(h.base, "releases"), 0700); err != nil {
		t.Fatal(err)
	}
	return h
}
func (h helperFixture) run(input string, args ...string) (string, error) {
	return h.runEnv(nil, input, args...)
}
func (h helperFixture) runEnv(env []string, input string, args ...string) (string, error) {
	c := exec.Command("bash", append([]string{h.script}, args...)...)
	c.Env = append(append(os.Environ(), env...), "VPN_HELPER_BASE="+h.base, "PATH="+h.bin+":"+os.Getenv("PATH"))
	c.Stdin = strings.NewReader(input)
	b, e := c.CombinedOutput()
	return string(b), e
}
func TestHelperInstallConfigOnly(t *testing.T) {
	h := newHelper(t)
	if out, e := h.run(`{"inbounds":[]}`, "install", helperID, helperImage); e != nil {
		t.Fatalf("install: %v %s", e, out)
	}
	dir := filepath.Join(h.base, "releases", helperID)
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 2 {
		t.Fatalf("release: %v %v", entries, e)
	}
	for _, n := range []string{"config.json", "image.txt"} {
		i, e := os.Lstat(filepath.Join(dir, n))
		if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 {
			t.Fatalf("unsafe %s: %v", n, e)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if string(b) != `{"inbounds":[]}` {
		t.Fatal("config changed")
	}
	if _, e := h.run(`{}`, "install", helperID, helperImage); e == nil {
		t.Fatal("duplicate accepted")
	}
	if _, e := os.Stat(filepath.Join(h.base, "releases", ".tmp-"+helperID)); !os.IsNotExist(e) {
		t.Fatal("temporary release remains")
	}
}
func TestHelperInstallRejectsInvalidImageAndOversize(t *testing.T) {
	for _, tc := range []struct{ name, input, image string }{{"image", `{}`, "alpine:latest"}, {"size", strings.Repeat("x", 1048577), helperImage}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHelper(t)
			if _, e := h.run(tc.input, "install", helperID, tc.image); e == nil {
				t.Fatal("accepted invalid input")
			}
			es, _ := os.ReadDir(filepath.Join(h.base, "releases"))
			if len(es) != 0 {
				t.Fatal("partial release remains")
			}
		})
	}
}

func TestHelperSealAndStop(t *testing.T) {
	h := newHelper(t)
	for _, id := range []string{helperID, "20260929T120001000000000Z"} {
		if out, e := h.run(`{}`, "install", id, helperImage); e != nil {
			t.Fatal(out, e)
		}
		if out, e := h.run("", "activate", id); e != nil {
			t.Fatal(out, e)
		}
	}
	if out, e := h.run("", "seal", "20260929T120001000000000Z"); e != nil {
		t.Fatal(out, e)
	}
	if _, e := os.Lstat(filepath.Join(h.base, "previous")); !os.IsNotExist(e) {
		t.Fatal("previous remains")
	}
	if out, e := h.run("", "stop"); e != nil {
		t.Fatal(out, e)
	}
	if _, e := os.Lstat(filepath.Join(h.base, "current")); !os.IsNotExist(e) {
		t.Fatal("current remains")
	}
	b, _ := os.ReadFile(filepath.Join(h.base, "docker.log"))
	if !strings.HasSuffix(string(b), "rm -f vpn-xray\n") {
		t.Fatal("container not removed")
	}
}

func TestHelperRollbackFirstReleaseToEmpty(t *testing.T) {
	h := newHelper(t)
	if out, e := h.run(`{}`, "install", helperID, helperImage); e != nil {
		t.Fatal(out, e)
	}
	if out, e := h.run("", "activate", helperID); e != nil {
		t.Fatal(out, e)
	}
	out, e := h.run("", "rollback")
	if e != nil || !strings.Contains(out, "rolled back to empty") {
		t.Fatalf("rollback: %v %s", e, out)
	}
	if _, e := os.Lstat(filepath.Join(h.base, "current")); !os.IsNotExist(e) {
		t.Fatal("current remains")
	}
	b, _ := os.ReadFile(filepath.Join(h.base, "docker.log"))
	if !strings.HasSuffix(string(b), "rm -f vpn-xray\n") {
		t.Fatal("container remains")
	}
}

type realHelperRunner struct{ helperFixture }

func (h realHelperRunner) Run(_ context.Context, _ registry.Server, _ bool, cmd string, input []byte) ([]byte, error) {
	args := strings.Fields(cmd)[2:]
	out, err := h.run(string(input), args...)
	return []byte(out), err
}
func TestDeployFirstReleaseReportsRolledBack(t *testing.T) {
	h := newHelper(t)
	r := testReg(t)
	r.Pins.ServerImage = helperImage
	res := Servers(context.Background(), r, realHelperRunner{h}, VerifyFunc(func(context.Context, registry.Server) error { return errors.New("verify failed") }), "kz", StopOnError, helperID)
	if len(res) != 1 || res[0].Err == nil || !res[0].RolledBack {
		t.Fatalf("result: %+v", res)
	}
	if _, e := os.Lstat(filepath.Join(h.base, "current")); !os.IsNotExist(e) {
		t.Fatal("current remains")
	}
}

// Reproduces the review's stale activation race using an actual flock waiter.
func TestHelperWaitingActivateCannotCrossSeal(t *testing.T) {
	h := newHelper(t)
	old, clean := helperID, "20260929T120001000000000Z"
	for _, id := range []string{old, clean} {
		if out, err := h.run("{}", "install", id, helperImage); err != nil {
			t.Fatal(out, err)
		}
		if out, err := h.run("", "activate", id); err != nil {
			t.Fatal(out, err)
		}
	}
	// Pause seal while it owns the lock, before removing previous.
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/bash\nif [[ $* == *previous* ]]; then touch \"$VPN_HELPER_BASE/sealing\"; while [[ ! -e $VPN_HELPER_BASE/release-seal ]]; do sleep 0.01; done; fi\nexec " + rm + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(h.bin, "rm"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	sealed := make(chan error, 1)
	go func() { _, err := h.run("", "seal", "20260929T120001000000000Z"); sealed <- err }()
	waitFile := func(name string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(h.base, name)); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("timeout waiting for " + name)
	}
	defer os.WriteFile(filepath.Join(h.base, "release-seal"), nil, 0600)
	waitFile("sealing")
	activated := make(chan error, 1)
	go func() { _, err := h.run("", "activate", old); activated <- err }()
	select {
	case err := <-activated:
		t.Fatalf("activation did not wait for seal: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	before, _ := os.ReadFile(filepath.Join(h.base, "docker.log"))
	os.WriteFile(filepath.Join(h.base, "release-seal"), nil, 0600)
	if err := <-sealed; err != nil {
		t.Fatal(err)
	}
	if err := <-activated; err == nil {
		t.Fatal("stale activation accepted")
	}
	after, _ := os.ReadFile(filepath.Join(h.base, "docker.log"))
	if string(before) != string(after) {
		t.Fatal("stale activation touched container")
	}
	barrier, _ := os.ReadFile(filepath.Join(h.base, "barrier"))
	if strings.TrimSpace(string(barrier)) != clean {
		t.Fatal("barrier not persisted")
	}
	// Even a surviving previous link cannot bypass the barrier.
	os.Symlink(filepath.Join(h.base, "releases", old), filepath.Join(h.base, "previous"))
	if _, err := h.run("", "rollback"); err == nil {
		t.Fatal("rollback crossed barrier")
	}
}

func waitBaseFile(t *testing.T, h helperFixture, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(h.base, name)); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout waiting for " + name)
}

// Regression: an install stuck reading a never-closing stdin must not hold the
// helper lock; a concurrent fail-closed stop still removes the container.
func TestHelperStopNotBlockedByStuckInstall(t *testing.T) {
	h := newHelper(t)
	if out, err := h.run(`{}`, "install", helperID, helperImage); err != nil {
		t.Fatal(out, err)
	}
	if out, err := h.run("", "activate", helperID); err != nil {
		t.Fatal(out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := "20260929T120001000000000Z"
	stuck := exec.CommandContext(ctx, "bash", h.script, "install", id, helperImage)
	stuck.Env = append(os.Environ(), "VPN_HELPER_BASE="+h.base, "PATH="+h.bin+":"+os.Getenv("PATH"))
	stdin, err := stuck.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := stuck.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = stuck.Wait() }()
	// The install is past staging and now blocks on stdin without the lock.
	waitBaseFile(t, h, filepath.Join("releases", ".tmp-"+id))
	done := make(chan error, 1)
	go func() { _, err := h.run("", "stop"); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop failed behind stuck install: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stop blocked behind stuck install")
	}
	if _, err := os.Stat(filepath.Join(h.base, "container")); !os.IsNotExist(err) {
		t.Fatal("container not removed")
	}
	// After EOF the install finishes and publishes the release normally.
	if _, err := stdin.Write([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stuck.Wait(); err != nil {
		t.Fatalf("install after EOF: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.base, "releases", id, "config.json")); err != nil {
		t.Fatal("release not published after EOF")
	}
}

// Regression: while another operation holds the lock, stop waits only its own
// short timeout instead of 120 s, then fails fast with a clear error.
func TestHelperStopShortLockTimeout(t *testing.T) {
	h := newHelper(t)
	if out, err := h.run(`{}`, "install", helperID, helperImage); err != nil {
		t.Fatal(out, err)
	}
	activated := make(chan error, 1)
	go func() { _, err := h.runEnv([]string{"VPN_HELPER_SLOW=3"}, "", "activate", helperID); activated <- err }()
	// docker.log appears once activate holds the lock inside run_container.
	waitBaseFile(t, h, "docker.log")
	start := time.Now()
	out, err := h.runEnv([]string{"VPN_HELPER_STOP_WAIT=1"}, "", "stop")
	if err == nil || !strings.Contains(out, "lock timeout") {
		t.Fatalf("stop must fail fast with lock timeout: %v %s", err, out)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("stop waited %v", elapsed)
	}
	if err := <-activated; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.base, "container")); err != nil {
		t.Fatal("container must survive a timed-out stop")
	}
}

// Regression: a staging .tmp-<id> directory of a concurrent install (it reads
// stdin without holding the lock) must never be pruned; prune counts only
// directories shaped like a release id.
func TestHelperPruneKeepsStagingTmp(t *testing.T) {
	h := newHelper(t)
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("20260929T120000%09dZ", i)
		if out, err := h.run("{}", "install", id, helperImage); err != nil {
			t.Fatal(out, err)
		}
	}
	tmp := filepath.Join(h.base, "releases", ".tmp-20260929T130000000000000Z")
	if err := os.MkdirAll(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := h.run("", "prune"); err != nil {
		t.Fatal(out, err)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatal("prune removed a staging .tmp directory")
	}
	es, _ := os.ReadDir(filepath.Join(h.base, "releases"))
	if len(es) != 6 { // 5 kept releases + the staging dir
		t.Fatalf("releases after prune: %v", es)
	}
	for _, e := range es {
		if e.Name() == "20260929T120000000000000Z" {
			t.Fatal("oldest release not pruned")
		}
	}
}

func TestHelperNanosecondReleaseIDs(t *testing.T) {
	h := newHelper(t)
	for _, id := range []string{"20260929T120000000000001Z", "20260929T120000000000002Z"} {
		if !releasePattern.MatchString(id) {
			t.Errorf("Go rejected nanosecond id")
		}
		if out, err := h.run("{}", "install", id, helperImage); err != nil {
			t.Errorf("helper rejected id: %s %v", out, err)
		}
	}
}

func TestReleaseIDSameSecond(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 1, time.UTC)
	a, b := ReleaseID(now), ReleaseID(now.Add(time.Nanosecond))
	if a != "20260929T120000000000001Z" || !(a < b) || !releasePattern.MatchString(b) {
		t.Fatal("IDs must preserve nanoseconds and order")
	}
	if releasePattern.MatchString("20260929T120000Z") {
		t.Fatal("variable width ID accepted")
	}
}
