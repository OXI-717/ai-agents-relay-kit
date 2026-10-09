// Package keychain stores vpn-registry credentials in the macOS login keychain.
package keychain

import (
	"fmt"
	"os/exec"
	"strings"
)

const service = "vpn-registry"

func Get(account string) (string, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", service, "-a", account, "-w").Output()
	if err != nil {
		return "", fmt.Errorf("keychain %s/%s: not found (see plan Task 0)", service, account)
	}
	return strings.TrimSpace(string(out)), nil
}

func Set(account, value string) error {
	cmd := exec.Command("security", "add-generic-password", "-U", "-s", service, "-a", account, "-w", value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain set %s: %v: %s", account, err, out)
	}
	return nil
}
