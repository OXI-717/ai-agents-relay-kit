// Command vpn-agent runs on each VPN server under systemd timer: collects xray
// traffic deltas into a disk spool and ships signed batches to the worker.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/agent"
	"github.com/OXI-717/ai-agents-relay-kit/internal/xraystats"
)

type config struct {
	Server    string `json:"server"`
	APIAddr   string `json:"api_addr"`   // 127.0.0.1:10085
	IngestURL string `json:"ingest_url"` // https://sub.…/ingest
	KeyFile   string `json:"key_file"`   // hex HMAC key, 0600
	StateDir  string `json:"state_dir"`
}

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "vpn-agent: "+f+"\n", a...); os.Exit(1) }

func main() {
	cfgPath := flag.String("config", "/etc/vpn-agent/agent.json", "agent config")
	noSend := flag.Bool("no-send", false, "collect into spool only (used before a managed xray restart)")
	supervise := flag.Bool("supervise", false, "xray health check + restart via vpn-helper (root unit)")
	helperPath := flag.String("helper", "/usr/local/sbin/vpn-helper", "vpn-helper path for -supervise")
	flag.Parse()
	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		die("config: %v", err)
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		die("config: %v", err)
	}
	if *supervise {
		health, helper := agent.NewSupervisor(cfg.APIAddr, *helperPath)
		res := agent.SuperviseOnce(context.Background(), health, helper, agent.SuperviseStateFile, 2)
		fmt.Printf("vpn-supervisor: healthy=%v fails=%d restarted=%v %s\n", res.Healthy, res.Fails, res.Restarted, res.Note)
		if !res.Healthy {
			// ненулевой код: в journal видно, что цикл нездоров (unit не failed — oneshot)
			os.Exit(3)
		}
		return
	}
	if cfg.Server == "" || cfg.APIAddr == "" || cfg.StateDir == "" {
		die("config: server, api_addr and state_dir are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	src := xraystats.New(cfg.APIAddr)
	batch, err := agent.Collect(ctx, cfg.Server, cfg.StateDir, src, time.Now())
	if err != nil {
		die("collect: %v", err)
	}
	if *noSend {
		fmt.Printf("collected batch %s\n", batch.BatchID)
		return
	}
	key, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		die("key: %v", err)
	}
	sent, err := agent.Flush(ctx, cfg.StateDir, strings.TrimSpace(string(key)), poster(cfg.IngestURL), time.Now())
	if err != nil {
		// The packet stays in spool; a failed send is not a crash-level error
		// for the timer, but log it loudly enough for the journal.
		fmt.Fprintf(os.Stderr, "vpn-agent: sent %d, flush: %v\n", sent, err)
		os.Exit(1)
	}
	fmt.Printf("batch %s spooled, %d packet(s) sent\n", batch.BatchID, sent)
}

func poster(url string) agent.Poster {
	return func(ctx context.Context, hdr map[string]string, body []byte) error {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("ingest %s", resp.Status)
		}
		return nil
	}
}
