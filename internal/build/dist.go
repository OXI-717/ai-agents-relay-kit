package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// WriteDist writes secret-bearing artifacts: dirs 0700, files 0600.
func WriteDist(dir string, files map[string][]byte) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("dist must be a real directory")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.Chmod(".", 0700); err != nil {
		return err
	}
	for name, body := range files {
		if !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." {
			return fmt.Errorf("invalid dist path")
		}
		parts := strings.Split(filepath.Dir(name), string(filepath.Separator))
		parent := "."
		for _, part := range parts {
			if part == "." {
				continue
			}
			parent = filepath.Join(parent, part)
			info, e := root.Lstat(parent)
			if os.IsNotExist(e) {
				e = root.Mkdir(parent, 0700)
			} else if e == nil && !info.IsDir() {
				return fmt.Errorf("dist directory is not a real directory")
			}
			if e != nil {
				return e
			}
			if e = root.Chmod(parent, 0700); e != nil {
				return e
			}
		}
		if info, e := root.Lstat(name); e == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("dist file is not a regular file")
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		f, e := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return e
		}
		// Repair permissions before writing or truncating existing secret-bearing files.
		if e = f.Chmod(0600); e == nil {
			e = f.Truncate(0)
		}
		if e == nil {
			_, e = f.Write(body)
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
