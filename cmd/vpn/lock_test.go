package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/deploy"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

// Adapted from review-main_test.go: A pauses at KV creation after persisting
// pending targets; B must fail before loading or modifying the registry.
func TestThirdReviewConcurrentJournalLostUpdate(t *testing.T) {
	d := t.TempDir()
	reg := filepath.Join(d, "registry")
	if err := os.CopyFS(reg, os.DirFS("../../testdata/registry")); err != nil {
		t.Fatal(err)
	}
	original, err := registry.Load(reg)
	if err != nil {
		t.Fatal(err)
	}
	token := original.Secrets.Users["bob"].Token
	want := []string{deploy.KVKey(token, "incy"), deploy.KVKey(token, "incy:routing"), deploy.KVKey(token, "happ"), deploy.KVKey(token, "happ:routing")}
	bin := filepath.Join(d, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	vpn := filepath.Join(bin, "vpn")
	if out, err := exec.Command("go", "build", "-o", vpn, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	for name, script := range map[string]string{
		"security": `#!/bin/sh
if [ "$PAUSE_KV" = yes ]; then
 touch "$TEST_SYNC/paused"
 i=0
 while [ ! -f "$TEST_SYNC/resume" ]; do
  i=$((i+1)); [ "$i" -lt 1000 ] || exit 1
  sleep 0.01
 done
fi
exit 1
`,
		"ssh":     "#!/bin/sh\nexit 1\n",
		"pbpaste": "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := func(args ...string) *exec.Cmd {
		c := exec.CommandContext(ctx, vpn, append([]string{"--registry", reg}, args...)...)
		c.Dir = d
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_SYNC="+d, "PAUSE_KV=no")
		return c
	}
	first := command("user", "revoke", "bob")
	first.Env = append(first.Env, "PAUSE_KV=yes")
	var output bytes.Buffer
	first.Stdout = &output
	first.Stderr = &output
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		os.WriteFile(filepath.Join(d, "resume"), nil, 0600)
		if !waited {
			first.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(d, "paused")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A did not reach KV factory")
		}
		time.Sleep(10 * time.Millisecond)
	}
	assertPending := func() {
		t.Helper()
		h, err := loadRevocations(reg)
		if err != nil || len(h) != 1 || h[0].User != "bob" || !reflect.DeepEqual(h[0].PendingKVKeys, want) {
			t.Fatal("A pending targets lost or modified")
		}
	}
	assertPending()
	before, err := os.ReadFile(filepath.Join(reg, "secrets.plain.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"user", "revoke", "alice"}, {"user", "add", "new", "New"}, {"uuids", "fill"},
		{"server", "keys", "kz"}, {"server", "bootstrap", "kz"}, {"--from-clipboard", "import"},
		{"deploy"}, {"deploy", "servers"}, {"deploy", "subs"}, {"user", "bundle", "alice"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, err := command(args...).CombinedOutput()
			if err == nil || !strings.Contains(string(out), "другая операция vpn уже идёт") {
				t.Errorf("expected lock rejection: %v %s", err, out)
			}
		})
	}
	after, err := os.ReadFile(filepath.Join(reg, "secrets.plain.yaml"))
	if err != nil || !bytes.Equal(before, after) {
		t.Error("B modified secrets while A held lock")
	}
	assertPending()
	if err := os.WriteFile(filepath.Join(d, "resume"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	err = first.Wait()
	waited = true
	if err == nil || !strings.Contains(output.String(), "revoke incomplete") {
		t.Fatalf("expected offline revoke: %v %s", err, output.String())
	}
	assertPending()
	// Process exit must release the lock, including on failure via die/os.Exit.
	out, err := command("user", "revoke", "alice").CombinedOutput()
	if err == nil || strings.Contains(string(out), "другая операция vpn") || !strings.Contains(string(out), "revoke incomplete") {
		t.Fatalf("lock not released: %v %s", err, out)
	}
	h, err := loadRevocations(reg)
	if err != nil || len(h) != 2 || !reflect.DeepEqual(h[0].PendingKVKeys, want) || len(h[1].PendingKVKeys) != 4 {
		t.Fatal("sequential revoke lost pending keys")
	}
}
