package deploy

import (
	"bytes"
	"context"
	"github.com/OXI-717/ai-agents-relay-kit/internal/build"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"testing"
)

type installRunner struct {
	fakeRunner
	stdin []byte
}

func (f *installRunner) Run(ctx context.Context, s registry.Server, root bool, cmd string, in []byte) ([]byte, error) {
	if in != nil {
		f.stdin = in
	}
	return f.fakeRunner.Run(ctx, s, root, cmd, in)
}
func TestInstallCommandConfigStdin(t *testing.T) {
	r := testReg(t)
	f := &installRunner{}
	Servers(context.Background(), r, f, okVerify, "kz", StopOnError, helperID)
	want := "sudo /usr/local/sbin/vpn-helper install " + helperID + " " + r.Pins.ServerImage
	if f.calls[0].Cmd != want {
		t.Fatalf("install command: %s", f.calls[0].Cmd)
	}
	cfg, e := build.ServerConfig(r, r.Servers[0])
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(f.stdin, cfg) {
		t.Fatal("stdin is not config JSON")
	}
}

func TestInstallRejectsShellArgumentsBeforeSSH(t *testing.T) {
	for _, which := range []string{"image", "id"} {
		t.Run(which, func(t *testing.T) {
			r := testReg(t)
			id := helperID
			if which == "image" {
				r.Pins.ServerImage = "bad; id"
			} else {
				id = "bad; id"
			}
			f := &fakeRunner{}
			res := Servers(context.Background(), r, f, okVerify, "kz", StopOnError, id)
			if len(f.calls) != 0 || res[0].Err == nil {
				t.Fatal("unsafe install argument reached SSH")
			}
		})
	}
}
