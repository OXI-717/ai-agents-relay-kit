package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/cf"
	"github.com/OXI-717/ai-agents-relay-kit/internal/deploy"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/remote"
	"github.com/OXI-717/ai-agents-relay-kit/internal/users"
	"gopkg.in/yaml.v3"
)

type revokeResult struct {
	Step string
	Err  error
}
type revocationRecord struct {
	KVDeleted     bool              `yaml:"kv_deleted,omitempty"`
	User          string            `yaml:"user"`
	Date          string            `yaml:"date"`
	Nodes         map[string]string `yaml:"nodes"`
	PendingKVKeys []string          `yaml:"pending_kv_keys,omitempty"`
}

// The CLI holds .vpn.lock from before registry.Load through the final journal write.
// Each stage is attempted independently, even if persistence or subscriptions fail.
func revokeUser(ctx context.Context, r *registry.Registry, id string, kvFactory func() (*cf.KV, error), run remote.Runner, check deploy.Verifier) ([]revokeResult, error) {
	// Persist non-secret deletion targets before destroying the token.
	knownUser := false
	for _, u := range r.Users {
		if u.ID == id {
			knownUser = true
		}
	}
	if !knownUser {
		return nil, fmt.Errorf("unknown user %s", id)
	}
	history, err := loadRevocations(r.Dir)
	if err != nil {
		return nil, fmt.Errorf("read revocation history: %w", err)
	}
	token := r.Secrets.Users[id].Token
	keys := []string{}
	seen := map[string]bool{}
	knownRecord := false
	addKey := func(k string) {
		if !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	for _, old := range history {
		if old.User == id {
			knownRecord = knownRecord || old.KVDeleted || len(old.PendingKVKeys) > 0
			for _, k := range old.PendingKVKeys {
				addKey(k)
			}
		}
	}
	if token != "" {
		for _, format := range []string{"incy", "incy:routing", "happ", "happ:routing"} {
			addKey(deploy.KVKey(token, format))
		}
	}
	now := time.Now().UTC()
	record := revocationRecord{User: id, Date: now.Format(time.RFC3339), Nodes: map[string]string{}, PendingKVKeys: keys}
	history = append(history, record)
	if err := saveRevocations(r.Dir, history); err != nil {
		return nil, fmt.Errorf("persist pending KV keys: %w", err)
	}
	if err := users.Revoke(r, id); err != nil {
		return nil, err
	}
	var results []revokeResult
	results = append(results, revokeResult{"registry secrets", registry.SaveSecrets(r.Dir, r.Secrets)})
	results = append(results, revokeResult{"registry users", registry.SaveUsers(r.Dir, r.Users)})
	kv, kvErr := kvFactory()
	delErr := kvErr
	if delErr == nil {
		if token == "" && !knownRecord {
			delErr = fmt.Errorf("subscription token unavailable; deletion unconfirmed")
		} else if len(keys) != 0 {
			delErr = kv.BulkDelete(ctx, keys)
		}
	}
	results = append(results, revokeResult{"subscription delete", delErr})
	// Only confirmed deletion clears pending targets. A failed history write leaves
	// the durable pre-operation record intact, making another retry harmless.
	if delErr == nil {
		for i := range history {
			if history[i].User == id {
				history[i].PendingKVKeys = nil
				history[i].KVDeleted = true
			}
		}
		record.PendingKVKeys = nil
		record.KVDeleted = true
	}
	for _, res := range deploy.Servers(ctx, r, run, check, "", deploy.Revoke, deploy.ReleaseID(now)) {
		step := "node " + res.Server
		if res.Status == "never deployed" {
			step += " (never deployed)"
		}
		results = append(results, revokeResult{step, res.Err})
		record.Nodes[res.Server] = "ok"
		if res.Err != nil {
			record.Nodes[res.Server] = "failed"
		}
	}
	subsErr := kvErr
	if subsErr == nil {
		_, _, subsErr = deploy.Subs(ctx, r, kv, now.Unix())
	}
	results = append(results, revokeResult{"subscriptions publish", subsErr})
	history[len(history)-1] = record
	results = append(results, revokeResult{"revocation history", saveRevocations(r.Dir, history)})
	for _, res := range results {
		if res.Err != nil {
			return results, fmt.Errorf("revoke incomplete: unconfirmed results")
		}
	}
	return results, nil
}

func loadRevocations(dir string) ([]revocationRecord, error) {
	b, err := os.ReadFile(filepath.Join(dir, "state", "revocations.yaml"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var history []revocationRecord
	err = yaml.Unmarshal(b, &history)
	return history, err
}

func appendRevocation(dir string, record revocationRecord) error {
	history, err := loadRevocations(dir)
	if err != nil {
		return err
	}
	return saveRevocations(dir, append(history, record))
}

// Replace the journal atomically, syncing both data and the directory before
// callers may remove secrets. Interrupted updates retain the preceding journal.
func saveRevocations(dir string, history []revocationRecord) error {
	path := filepath.Join(dir, "state")
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	b, err := yaml.Marshal(history)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(path, ".revocations-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(path, "revocations.yaml")); err != nil {
		return err
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
