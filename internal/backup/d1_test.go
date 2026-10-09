package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestD1ExportEncrypts(t *testing.T) {
	work := t.TempDir()
	out := t.TempDir()
	var gotArgs [][]string
	fake := func(ctx context.Context, dir string, stdin []byte, name string, args ...string) ([]byte, error) {
		gotArgs = append(gotArgs, append([]string{name}, args...))
		switch name {
		case "wrangler":
			// emulate export: --output <dir>
			o := args[len(args)-1]
			return nil, os.WriteFile(filepath.Join(o, "0001.dump.sql"), []byte("CREATE TABLE t(x);"), 0o600)
		case "age":
			if len(stdin) == 0 || !strings.Contains(string(stdin), "CREATE TABLE") {
				return nil, fmt.Errorf("age got no stdin")
			}
			dst := args[len(args)-1]
			return nil, os.WriteFile(dst, append([]byte("AGE:"), stdin...), 0o600)
		}
		return nil, fmt.Errorf("unexpected %s", name)
	}
	paths, err := D1(context.Background(), fake, work, out, "vpn-registry", "AGE-SECRET-KEY-TEST", time.Unix(1760000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || !strings.HasSuffix(paths[0], ".sql.age") {
		t.Fatalf("paths %v", paths)
	}
	b, _ := os.ReadFile(paths[0])
	if string(b) != "AGE:CREATE TABLE t(x);" {
		t.Fatalf("content %q", b)
	}
	if fi, _ := os.Stat(paths[0]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if gotArgs[0][0] != "wrangler" || gotArgs[0][2] != "export" {
		t.Fatalf("args %v", gotArgs)
	}
}

func TestD1NoDatabase(t *testing.T) {
	if _, err := D1(context.Background(), nil, ".", t.TempDir(), "", "k", time.Now()); err == nil {
		t.Fatal("empty database accepted")
	}
}
