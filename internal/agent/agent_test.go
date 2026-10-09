package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/xraystats"
)

type fakeSrc struct {
	vals   map[string]int64
	uptime uint32
	online int
}

func (f *fakeSrc) QueryStats(context.Context, string) (map[string]int64, error) { return f.vals, nil }
func (f *fakeSrc) SysStats(context.Context) (xraystats.SysStats, error) {
	return xraystats.SysStats{Uptime: f.uptime, NumGoroutine: 10, Alloc: 1 << 20}, nil
}
func (f *fakeSrc) OnlineIPs(context.Context) (int, error) { return f.online, nil }

var t0 = time.Unix(1_760_000_000, 0)

func stats(email string, up, down int64) map[string]int64 {
	return map[string]int64{
		"user>>>" + email + ">>>traffic>>>uplink":   up,
		"user>>>" + email + ">>>traffic>>>downlink": down,
	}
}

func TestCollectDelta(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSrc{vals: stats("user@kz", 100, 200), uptime: 300}
	b, err := Collect(context.Background(), "kz", dir, src, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Stats) != 1 || b.Stats[0].Up != 100 || b.Stats[0].Down != 200 {
		t.Fatalf("first collect %+v", b.Stats)
	}
	if b.Stats[0].UserRef != registry.UserRef("user") {
		t.Fatalf("user_ref %s", b.Stats[0].UserRef)
	}
	if b.Heartbeat.Gap {
		t.Fatal("gap on first run")
	}
	// Same launch (uptime advanced 300s, now advanced 300s): delta only.
	src.vals = stats("user@kz", 150, 260)
	src.uptime = 600
	b2, err := Collect(context.Background(), "kz", dir, src, t0.Add(300*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if b2.Stats[0].Up != 50 || b2.Stats[0].Down != 60 {
		t.Fatalf("delta %+v", b2.Stats[0])
	}
	if b2.BatchID == b.BatchID {
		t.Fatal("batch_id reused")
	}
	// No traffic → zero delta.
	src.uptime = 900
	b3, _ := Collect(context.Background(), "kz", dir, src, t0.Add(600*time.Second))
	if b3.Stats[0].Up != 0 {
		t.Fatalf("expected zero delta, got %+v", b3.Stats[0])
	}
}

func TestCollectXrayRestart(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSrc{vals: stats("user@kz", 100, 0), uptime: 300}
	if _, err := Collect(context.Background(), "kz", dir, src, t0); err != nil {
		t.Fatal(err)
	}
	// xray restarted: uptime reset, counters reset, same wall-clock step.
	src.vals = stats("user@kz", 5, 0)
	src.uptime = 10
	b, err := Collect(context.Background(), "kz", dir, src, t0.Add(300*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if b.Stats[0].Up != 5 {
		t.Fatalf("restart delta must be absolute value, got %d", b.Stats[0].Up)
	}
	if !b.Heartbeat.Gap {
		t.Fatal("restart must flag gap")
	}
}

func TestServiceTrafficSeparate(t *testing.T) {
	dir := t.TempDir()
	m := stats("user@am", 10, 10)
	for k, v := range stats("svc:tw>am", 99, 99) {
		m[k] = v
	}
	src := &fakeSrc{vals: m, uptime: 5}
	b, err := Collect(context.Background(), "am", dir, src, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.ServiceStats) != 1 || b.ServiceStats[0].Key != "svc:tw>am" {
		t.Fatalf("svc %+v", b.ServiceStats)
	}
	if len(b.Stats) != 1 {
		t.Fatalf("user %+v", b.Stats)
	}
}

func TestFlushResendAfterLostAck(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSrc{vals: stats("user@kz", 10, 0), uptime: 60}
	if _, err := Collect(context.Background(), "kz", dir, src, t0); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("ab", 32)
	var posts []map[string]string
	fail := Poster(func(ctx context.Context, h map[string]string, body []byte) error {
		posts = append(posts, h)
		return context.DeadlineExceeded // ACK lost: packet stays
	})
	n, err := Flush(context.Background(), dir, key, fail, t0)
	if n != 0 || err == nil || len(posts) != 1 {
		t.Fatalf("n=%d err=%v posts=%d", n, err, len(posts))
	}
	ok := Poster(func(ctx context.Context, h map[string]string, body []byte) error {
		posts = append(posts, h)
		var b Batch
		if err := json.Unmarshal(body, &b); err != nil {
			return err
		}
		if h["X-VPN-Batch"] != b.BatchID || h["X-VPN-Server"] != "kz" || h["X-VPN-Signature"] == "" {
			t.Errorf("headers %v", h)
		}
		return nil
	})
	n, err = Flush(context.Background(), dir, key, ok, t0)
	if err != nil || n != 1 || len(posts) != 2 {
		t.Fatalf("resend n=%d err=%v", n, err)
	}
	if es, _ := os.ReadDir(spoolDir(dir)); len(es) != 0 {
		t.Fatal("spool not empty after ACK")
	}
}

func TestSpoolGC(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(spoolDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(spoolDir(dir), "old.json")
	if err := os.WriteFile(old, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldT := t0.Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(old, oldT, oldT); err != nil {
		t.Fatal(err)
	}
	gcSpool(dir, t0)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old packet not collected")
	}
}

func TestSignStable(t *testing.T) {
	key := strings.Repeat("cd", 32)
	h, err := Sign(key, "kz", 1700000000, "bid", []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if len(h["X-VPN-Signature"]) != 64 {
		t.Fatalf("sig %q", h["X-VPN-Signature"])
	}
	h2, _ := Sign(key, "kz", 1700000000, "bid", []byte("body"))
	if h["X-VPN-Signature"] != h2["X-VPN-Signature"] {
		t.Fatal("signature not deterministic")
	}
	if _, err := Sign("zz", "kz", 0, "b", nil); err == nil {
		t.Fatal("bad key accepted")
	}
}
