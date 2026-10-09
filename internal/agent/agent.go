// Package agent collects per-user xray traffic deltas, queues them in a disk
// spool and ships signed batches to the worker /ingest endpoint (spec §7.1).
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/xraystats"
)

const (
	maxPacket  = 64 * 1024
	spoolMaxAge = 7 * 24 * time.Hour
	// launchBucket: start-time estimates within one bucket are the same launch.
	// The agent is unprivileged and cannot read the container PID, so the launch
	// identifier is floor(now - uptime) rounded to minutes (spec deviation §7.1).
	launchBucket = 60
)

const Version = "0.2.0"

// StatsSource is the slice of the xray StatsService the agent needs.
type StatsSource interface {
	QueryStats(ctx context.Context, pattern string) (map[string]int64, error)
	SysStats(ctx context.Context) (xraystats.SysStats, error)
	OnlineIPs(ctx context.Context) (int, error)
}

type Stat struct {
	UserRef string `json:"user_ref"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
}

type SvcStat struct {
	Key  string `json:"key"` // svc:<relay>><exit>
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type Heartbeat struct {
	AgentVersion string `json:"agent_version"`
	XrayUptime   uint32 `json:"xray_uptime"`
	Goroutines   uint32 `json:"goroutines"`
	Alloc        uint64 `json:"alloc"`
	Online       int    `json:"online"`
	Spool        int    `json:"spool"`
	Gap          bool   `json:"gap,omitempty"`
}

type Batch struct {
	SchemaVersion int       `json:"schema_version"`
	Server        string    `json:"server"`
	BatchID       string    `json:"batch_id"`
	MeasuredAt    int64     `json:"measured_at"`
	Stats         []Stat    `json:"stats"`
	ServiceStats  []SvcStat `json:"service_stats"`
	Heartbeat     Heartbeat `json:"heartbeat"`
}

// checkpoint survives restarts: absolute counters of the previous run plus the
// launch identifier of the xray process they were read from.
type checkpoint struct {
	Launch string           `json:"launch"`
	Values map[string]int64 `json:"values"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }
func spoolDir(dir string) string  { return filepath.Join(dir, "spool") }

func loadCheckpoint(dir string) checkpoint {
	var cp checkpoint
	b, err := os.ReadFile(statePath(dir))
	if err == nil {
		_ = json.Unmarshal(b, &cp)
	}
	if cp.Values == nil {
		cp.Values = map[string]int64{}
	}
	return cp
}

func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// userStatKey parses "user>>><email>>>>traffic>>>(uplink|downlink)".
func userStatKey(name string) (email, dir string, ok bool) {
	const pre = "user>>>"
	if !strings.HasPrefix(name, pre) {
		return "", "", false
	}
	rest := name[len(pre):]
	i := strings.Index(rest, ">>>traffic>>>")
	if i <= 0 {
		return "", "", false
	}
	d := rest[i+len(">>>traffic>>>"):]
	if d != "uplink" && d != "downlink" {
		return "", "", false
	}
	return rest[:i], d, true
}

// userID extracts the user part of an email: "user@kz/am" → "user".
func userID(email string) string {
	if i := strings.Index(email, "@"); i >= 0 {
		return email[:i]
	}
	return email
}

func launchID(now time.Time, uptime uint32) string {
	start := now.Unix() - int64(uptime)
	return fmt.Sprintf("%d", start/launchBucket)
}

// Collect reads stats, computes deltas against the checkpoint, spools a signed
// batch and commits the checkpoint. On any stats error the checkpoint is left
// untouched so the next run does not lose counters.
func Collect(ctx context.Context, server, stateDir string, src StatsSource, now time.Time) (*Batch, error) {
	vals, err := src.QueryStats(ctx, "user>>>")
	if err != nil {
		return nil, fmt.Errorf("query stats: %w", err)
	}
	sys, err := src.SysStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("sys stats: %w", err)
	}
	online, err := src.OnlineIPs(ctx)
	if err != nil {
		online = -1 // online list is best-effort; counters already read
	}
	cp := loadCheckpoint(stateDir)
	launch := launchID(now, sys.Uptime)
	restart := cp.Launch != "" && cp.Launch != launch

	type agg struct{ up, down int64 }
	users := map[string]*agg{}
	svcs := map[string]*agg{}
	for name, cur := range vals {
		email, dir, ok := userStatKey(name)
		if !ok {
			continue
		}
		delta := cur
		if !restart {
			if prev, ok := cp.Values[name]; ok && cur >= prev {
				delta = cur - prev
			}
		}
		if strings.HasPrefix(email, "svc:") {
			a := svcs[email]
			if a == nil {
				a = &agg{}
				svcs[email] = a
			}
			if dir == "uplink" {
				a.up = delta
			} else {
				a.down = delta
			}
		} else {
			ref := registry.UserRef(userID(email))
			a := users[ref]
			if a == nil {
				a = &agg{}
				users[ref] = a
			}
			if dir == "uplink" {
				a.up = delta
			} else {
				a.down = delta
			}
		}
	}
	b := &Batch{
		SchemaVersion: 1,
		Server:        server,
		MeasuredAt:    now.Unix(),
		Heartbeat: Heartbeat{
			AgentVersion: Version,
			XrayUptime:   sys.Uptime,
			Goroutines:   sys.NumGoroutine,
			Alloc:        sys.Alloc,
			Online:       online,
			Gap:          restart,
		},
	}
	for ref, a := range users {
		b.Stats = append(b.Stats, Stat{UserRef: ref, Up: a.up, Down: a.down})
	}
	for k, a := range svcs {
		b.ServiceStats = append(b.ServiceStats, SvcStat{Key: k, Up: a.up, Down: a.down})
	}
	sort.Slice(b.Stats, func(i, j int) bool { return b.Stats[i].UserRef < b.Stats[j].UserRef })
	sort.Slice(b.ServiceStats, func(i, j int) bool { return b.ServiceStats[i].Key < b.ServiceStats[j].Key })
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	b.BatchID = id.String()

	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if len(body) > maxPacket {
		return nil, fmt.Errorf("batch %d bytes exceeds %d", len(body), maxPacket)
	}
	if err := os.MkdirAll(spoolDir(stateDir), 0o700); err != nil {
		return nil, err
	}
	b.Heartbeat.Spool = spoolSize(stateDir) + 1
	if body, err = json.Marshal(b); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(spoolDir(stateDir), b.BatchID+".json"), body, 0o600); err != nil {
		return nil, err
	}
	cp.Launch, cp.Values = launch, vals
	raw, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(statePath(stateDir), raw, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

func spoolSize(stateDir string) int {
	es, _ := os.ReadDir(spoolDir(stateDir))
	n := 0
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// Poster sends one batch body; returning nil means ACK (any 2xx).
type Poster func(ctx context.Context, hdr map[string]string, body []byte) error

// Flush posts spooled batches oldest-first and deletes them on ACK; it also
// drops packets older than spoolMaxAge.
func Flush(ctx context.Context, stateDir, keyHex string, post Poster, now time.Time) (sent int, err error) {
	if err := gcSpool(stateDir, now); err != nil {
		return 0, err
	}
	es, err := os.ReadDir(spoolDir(stateDir))
	if err != nil {
		return 0, nil // no spool yet
	}
	names := []string{}
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // UUIDv7 sorts by creation time
	for _, name := range names {
		p := filepath.Join(spoolDir(stateDir), name)
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var b Batch
		if err := json.Unmarshal(body, &b); err != nil {
			_ = os.Remove(p) // corrupt packet can never be ACKed
			continue
		}
		hdr, err := Sign(keyHex, b.Server, now.Unix(), b.BatchID, body)
		if err != nil {
			return sent, err
		}
		if err := post(ctx, hdr, body); err != nil {
			return sent, err // keep the packet, retry next run
		}
		if err := os.Remove(p); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func gcSpool(stateDir string, now time.Time) error {
	es, err := os.ReadDir(spoolDir(stateDir))
	if err != nil {
		return nil
	}
	for _, e := range es {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if fi, err := e.Info(); err == nil && now.Sub(fi.ModTime()) > spoolMaxAge {
			_ = os.Remove(filepath.Join(spoolDir(stateDir), e.Name()))
		}
	}
	return nil
}
