package build

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDistPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dist")
	if err := WriteDist(dir, map[string][]byte{"users/alice/subscription.txt": []byte("synthetic")}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "users", "users/alice", "users/alice/subscription.txt"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0700)
		if !info.IsDir() {
			want = 0600
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s permissions %o, want %o", name, info.Mode().Perm(), want)
		}
	}
}

func TestWriteDistRepairsExistingPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dist")
	p := filepath.Join(dir, "users", "alice", "sub.txt")
	os.MkdirAll(filepath.Dir(p), 0755)
	os.WriteFile(p, []byte("old"), 0644)
	if e := WriteDist(dir, map[string][]byte{"users/alice/sub.txt": []byte("new")}); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"", "users", "users/alice", "users/alice/sub.txt"} {
		i, e := os.Stat(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		want := os.FileMode(0700)
		if !i.IsDir() {
			want = 0600
		}
		if i.Mode().Perm() != want {
			t.Errorf("%s mode %o", name, i.Mode().Perm())
		}
	}
}
func TestWriteDistRejectsEscapesAndSymlinks(t *testing.T) {
	for _, kind := range []string{"root", "parent", "file", "traversal", "absolute"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "dist")
			outside := filepath.Join(base, "outside")
			os.Mkdir(outside, 0755)
			os.WriteFile(filepath.Join(outside, "secret"), []byte("unchanged"), 0644)
			name := "sub/secret"
			os.MkdirAll(filepath.Join(dir, "sub"), 0700)
			switch kind {
			case "root":
				os.RemoveAll(dir)
				os.Symlink(outside, dir)
			case "parent":
				os.Remove(filepath.Join(dir, "sub"))
				os.Symlink(outside, filepath.Join(dir, "sub"))
			case "file":
				os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, name))
			case "traversal":
				name = "../outside/secret"
			case "absolute":
				name = filepath.Join(outside, "secret")
			}
			if e := WriteDist(dir, map[string][]byte{name: []byte("leak")}); e == nil {
				t.Fatal("unsafe path accepted")
			}
			b, _ := os.ReadFile(filepath.Join(outside, "secret"))
			i, _ := os.Stat(filepath.Join(outside, "secret"))
			if string(b) != "unchanged" || i.Mode().Perm() != 0644 {
				t.Fatal("outside changed")
			}
		})
	}
}
