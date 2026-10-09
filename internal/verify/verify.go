// Package verify proves a server works end-to-end: a real tunnel exits with the expected IP.
package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/OXI-717/ai-agents-relay-kit/internal/build"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

type Checker struct {
	r           *registry.Registry
	xray        string
	startTunnel func(context.Context, build.Profile) (*http.Client, func(), error)
	Report      func(key, expectedIP string, err error)
}

func New(r *registry.Registry, xrayBin string) *Checker { return &Checker{r: r, xray: xrayBin} }

func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func checkIP(body, want string) error {
	if got := strings.TrimSpace(body); got != want {
		return fmt.Errorf("exit ip %s, want %s", got, want)
	}
	return nil
}

func (c *Checker) profiles(s registry.Server) ([]build.Profile, error) {
	var out []build.Profile
	for _, u := range c.r.ActiveUsers() {
		ps, err := build.Profiles(c.r, u)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if p.Server.ID == s.ID || (s.Kind == "exit" && p.Exit.ID == s.ID) {
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no active user with this entry", s.ID)
	}
	return out, nil
}

// tunnel starts a local xray client and returns an http.Client through it.
func (c *Checker) tunnel(ctx context.Context, p build.Profile) (*http.Client, func(), error) {
	if c.startTunnel != nil {
		return c.startTunnel(ctx, p)
	}
	port, err := FreePort()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := build.ClientConfig(c.r, p, port, registry.RoutingProfile{})
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "vpn-verify-")
	if err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, c.xray, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); os.RemoveAll(dir) }
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 50; i++ {
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		stop()
		return nil, nil, err
	}
	tr := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, stop, nil
}

func (c *Checker) Server(ctx context.Context, s registry.Server) error {
	return c.server(ctx, s, false)
}

// ServerDirect checks only profiles whose entry is the server itself. Relay
// pairs are skipped: during deploy they can only be checked after the relays
// they enter through are updated.
func (c *Checker) ServerDirect(ctx context.Context, s registry.Server) error {
	return c.server(ctx, s, true)
}

func (c *Checker) server(ctx context.Context, s registry.Server, directOnly bool) error {
	ps, err := c.profiles(s)
	if err != nil {
		return err
	}
	var failures []error
	for _, p := range ps {
		if directOnly && p.Server.ID != s.ID {
			continue
		}
		err := c.checkProfile(ctx, p)
		if c.Report != nil {
			c.Report(p.Key, p.Exit.Host, err)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", p.Key, err))
		}
	}
	return errors.Join(failures...)
}

func (c *Checker) checkProfile(ctx context.Context, p build.Profile) error {
	hc, stop, err := c.tunnel(ctx, p)
	if err != nil {
		return err
	}
	defer stop()
	var last error
	for attempt := 0; attempt < 3; attempt++ { // container needs a moment after activate
		resp, err := hc.Get("https://api.ipify.org")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return checkIP(string(b), p.Exit.Host)
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("tunnel request failed: %w", last)
}

func (c *Checker) Load(ctx context.Context, s registry.Server, parallel int) (int, int, error) {
	ps, err := c.profiles(s)
	if err != nil {
		return 0, 0, err
	}
	ok, total := 0, 0
	var failures []error
	for _, p := range ps {
		n, want, err := c.loadProfile(ctx, p, parallel)
		ok += n
		total += want
		if c.Report != nil {
			c.Report(p.Key+" load", p.Exit.Host, err)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", p.Key, err))
		}
	}
	return ok, total, errors.Join(failures...)
}

func (c *Checker) loadProfile(ctx context.Context, p build.Profile, parallel int) (int, int, error) {
	hc, stop, err := c.tunnel(ctx, p)
	if err != nil {
		return 0, 0, err
	}
	defer stop()
	var mu sync.Mutex
	ok := 0
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := hc.Get("https://www.google.com/generate_204")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 204 {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	big := &http.Client{Transport: hc.Transport, Timeout: 120 * time.Second}
	resp, err := big.Get("https://speed.cloudflare.com/__down?bytes=20000000")
	if err != nil {
		return ok, parallel + 1, fmt.Errorf("download: %w", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != 20000000 {
		return ok, parallel + 1, fmt.Errorf("download got %d bytes: %v", n, err)
	}
	if ok != parallel {
		return ok + 1, parallel + 1, fmt.Errorf("parallel requests succeeded: %d/%d", ok, parallel)
	}
	return ok + 1, parallel + 1, nil
}
