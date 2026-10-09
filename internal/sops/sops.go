// Package sops wraps the sops binary; the age identity comes from the keychain.
package sops

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/OXI-717/ai-agents-relay-kit/internal/keychain"
)

func env() ([]string, error) {
	key, err := keychain.Get("age-key")
	if err != nil {
		return nil, err
	}
	return append(os.Environ(), "SOPS_AGE_KEY="+key), nil
}

func Decrypt(path string) ([]byte, error) {
	e, err := env()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", path)
	cmd.Env = e
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sops decrypt %s: %v: %s", path, err, stderr.String())
	}
	return out, nil
}

// Encrypt writes plain YAML encrypted to path; plain never touches disk unencrypted.
func Encrypt(plain []byte, path string) error {
	e, err := env()
	if err != nil {
		return err
	}
	cmd := exec.Command("sops", "--encrypt", "--input-type", "yaml", "--output-type", "yaml",
		"--filename-override", path, "/dev/stdin")
	cmd.Env = e
	cmd.Stdin = bytes.NewReader(plain)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("sops encrypt %s: %v: %s", path, err, stderr.String())
	}
	return os.WriteFile(path, out, 0o600)
}
