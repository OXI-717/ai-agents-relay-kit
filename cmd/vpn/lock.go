package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func mutatesRegistry(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "deploy" || args[0] == "import" {
		return true
	}
	switch strings.Join(args[:min(2, len(args))], " ") {
	case "user add", "user revoke", "user bundle", "uuids fill", "server keys", "server bootstrap":
		return true
	}
	return false
}

// Hold this descriptor for the entire operation, starting before registry.Load.
// Never unlink the lock file: waiters must all lock the same inode. Process exit
// also releases the lock when die calls os.Exit and deferred Close cannot run.
func lockRegistry(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, ".vpn.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("registry lock: %w", err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("другая операция vpn уже идёт")
		}
		return nil, fmt.Errorf("registry lock: %w", err)
	}
	return f, nil
}
