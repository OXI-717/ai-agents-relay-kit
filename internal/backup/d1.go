// Package backup exports the D1 database and encrypts the dump with the
// registry age key (spec §7.2: weekly export stored outside Cloudflare).
package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Exec abstracts external commands for tests: name+args → combined output.
type Exec func(ctx context.Context, dir string, stdin []byte, name string, args ...string) ([]byte, error)

func realExec(ctx context.Context, dir string, stdin []byte, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, firstArgs(args), err, trimLog(out))
	}
	return out, nil
}

func firstArgs(args []string) string {
	if len(args) > 2 {
		return strings.Join(args[:2], " ")
	}
	return strings.Join(args, " ")
}

func trimLog(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// D1 runs `wrangler d1 export <db> --remote --output <tmp>` inside workDir
// (the repo checkout, for wrangler.toml resolution), then encrypts every
// exported .sql file with `age` using the identity (its recipient) given, and
// writes <outDir>/d1-<db>-<ts>.sql.age (0600). Returns the output paths.
// The plaintext export never leaves a 0700 temp dir and is removed.
func D1(ctx context.Context, x Exec, workDir, outDir, database, ageKey string, now time.Time) ([]string, error) {
	if x == nil {
		x = realExec
	}
	if database == "" {
		return nil, fmt.Errorf("d1 database name is empty (registry cloudflare.d1_database)")
	}
	tmp, err := os.MkdirTemp("", "vpn-d1-export-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return nil, err
	}
	if _, err := x(ctx, workDir, nil, "wrangler", "d1", "export", database, "--remote", "--output", tmp); err != nil {
		return nil, err
	}
	// Encrypt to the key's own recipient: `age -e -i -` accepts an identity file.
	idf := filepath.Join(tmp, "age.key")
	if err := os.WriteFile(idf, []byte(ageKey+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	var out []string
	es, err := os.ReadDir(tmp)
	if err != nil {
		return nil, err
	}
	var sqls []string
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".sql") {
			sqls = append(sqls, e.Name())
		}
	}
	sort.Strings(sqls)
	if len(sqls) == 0 {
		return nil, fmt.Errorf("wrangler produced no .sql in %s", tmp)
	}
	ts := now.UTC().Format("20060102T150405Z")
	for _, name := range sqls {
		plain, err := os.ReadFile(filepath.Join(tmp, name))
		if err != nil {
			return out, err
		}
		base := strings.TrimSuffix(name, ".sql")
		dst := filepath.Join(outDir, fmt.Sprintf("d1-%s-%s-%s.sql.age", database, base, ts))
		enc, err := x(ctx, tmp, plain, "age", "-e", "-i", idf, "-o", dst)
		if err != nil {
			return out, fmt.Errorf("age: %w", err)
		}
		_ = enc
		if err := os.Chmod(dst, 0o600); err != nil {
			return out, err
		}
		out = append(out, dst)
	}
	return out, nil
}
