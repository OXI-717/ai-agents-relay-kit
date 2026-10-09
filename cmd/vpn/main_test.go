package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTestdata(t *testing.T) {
	out, err := exec.Command("go", "run", ".", "--registry", "../../testdata/registry", "validate").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "registry OK") {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestRevokeKeychainFailureStillAttemptsAllServers(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry")
	if err := os.CopyFS(reg, os.DirFS("../../testdata/registry")); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "security"), []byte("#!/bin/sh\nexit 1\n"), 0700)
	log := filepath.Join(dir, "ssh.log")
	os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TEST_SSH_LOG\"\nexit 1\n"), 0700)
	c := exec.Command("go", "run", ".", "--registry", reg, "user", "revoke", "bob")
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_SSH_LOG="+log)
	out, err := c.CombinedOutput()
	if err == nil {
		t.Fatal("incomplete revoke succeeded")
	}
	b, _ := os.ReadFile(log)
	for _, host := range []string{"192.0.2.10", "192.0.2.20"} {
		if !strings.Contains(string(b), host) {
			t.Errorf("server %s not attempted; output: %s", host, out)
		}
	}
	history, e := os.ReadFile(filepath.Join(reg, "state", "revocations.yaml"))
	if e != nil || !strings.Contains(string(history), "user: bob") {
		t.Errorf("missing revocation history: %v", e)
	}
	if strings.Contains(string(out), "revoked everywhere") {
		t.Fatal("false success")
	}
}

func TestDistClean(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "vpn")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	reg, _ := filepath.Abs("../../testdata/registry")
	os.MkdirAll(filepath.Join(dir, "dist", "users", "bob"), 0o700)
	os.WriteFile(filepath.Join(dir, "dist", "users", "bob", "subscription.txt"), []byte("x"), 0o600)
	c := exec.Command(bin, "--registry", reg, "dist", "clean")
	c.Dir = dir
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist")); !os.IsNotExist(err) {
		t.Fatal("dist with user artifacts still present")
	}
}

func TestRevokeRetryFlag(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry")
	if err := os.CopyFS(reg, os.DirFS("../../testdata/registry")); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "security"), []byte("#!/bin/sh\nexit 1\n"), 0700)
	os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nexit 1\n"), 0700)
	for _, extra := range [][]string{nil, {"--retry"}} {
		args := append([]string{"run", ".", "--registry", reg, "user", "revoke", "bob"}, extra...)
		c := exec.Command("go", args...)
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, err := c.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "node kz") || !strings.Contains(string(out), "node am") {
			t.Fatalf("retry failed to attempt nodes: %v %s", err, out)
		}
	}
}

func TestImportDuplicateIDDoesNotChangeRegistry(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry")
	if e := os.CopyFS(reg, os.DirFS("../../testdata/registry")); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(reg, "external.yaml"))
	secrets, _ := os.ReadFile(filepath.Join(reg, "secrets.plain.yaml"))
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "pbpaste"), []byte("#!/bin/sh\nprintf '%s\\n' 'vless://66666666-6666-4666-8666-666666666666@example.org:443#ext-one'\n"), 0700)
	c := exec.Command("go", "run", ".", "--registry", reg, "--from-clipboard", "import")
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	if out, e := c.CombinedOutput(); e == nil {
		t.Fatalf("duplicate accepted: %s", out)
	}
	after, _ := os.ReadFile(filepath.Join(reg, "external.yaml"))
	afterSec, _ := os.ReadFile(filepath.Join(reg, "secrets.plain.yaml"))
	if string(before) != string(after) || string(secrets) != string(afterSec) {
		t.Fatal("duplicate changed registry")
	}
}

func TestDeployDisabledWithoutLocalXray(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry")
	if e := os.CopyFS(reg, os.DirFS("../../testdata/registry")); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(reg, "servers.yaml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.ReplaceAll(string(b), "enabled: true", "enabled: false")), 0600)
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nexit 1\n"), 0700)
	c := exec.Command("go", "run", ".", "--registry", reg, "deploy", "servers")
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	out, e := c.CombinedOutput()
	if e != nil || !strings.Contains(string(out), "warning: kz") || !strings.Contains(string(out), "warning: am") || !strings.Contains(string(out), "never deployed") {
		t.Fatalf("disabled deploy: %v %s", e, out)
	}
}

func TestVerifyUnknownServerFails(t *testing.T) {
	out, err := exec.Command("go", "run", ".", "--registry", "../../testdata/registry", "--server", "missing", "verify").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "unknown server missing") {
		t.Fatalf("want unknown server failure, got %v: %s", err, out)
	}
}
