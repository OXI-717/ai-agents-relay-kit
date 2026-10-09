package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/OXI-717/ai-agents-relay-kit/internal/cf"
	"github.com/OXI-717/ai-agents-relay-kit/internal/deploy"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRevokeRetryAfterKeychainFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reg")
	if e := os.CopyFS(dir, os.DirFS("../../testdata/registry")); e != nil {
		t.Fatal(e)
	}
	r, e := registry.Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	tok := r.Secrets.Users["bob"].Token
	uuid := r.Secrets.UUIDs["bob@kz"]
	var events []string
	_, e = revokeUser(context.Background(), r, "bob", func() (*cf.KV, error) { return nil, errors.New("keychain offline") }, revokeRunner{&events}, nil)
	if e == nil {
		t.Fatal("false success")
	}
	history, err := loadRevocations(dir)
	if err != nil || len(history) != 1 || len(history[0].PendingKVKeys) != 4 {
		t.Fatal("pending keys not durable")
	}
	want := []string{deploy.KVKey(tok, "incy"), deploy.KVKey(tok, "incy:routing"), deploy.KVKey(tok, "happ"), deploy.KVKey(tok, "happ:routing")}
	if !reflect.DeepEqual(history[0].PendingKVKeys, want) {
		t.Fatal("wrong pending targets")
	}
	info, _ := os.Stat(filepath.Join(dir, "state/revocations.yaml"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe journal mode")
	}
	r, e = registry.Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	r.Users[0].Formats = []string{"broken"}
	deletes := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/bulk/delete") {
			deletes++
			var keys []string
			if err := json.NewDecoder(req.Body).Decode(&keys); err != nil || !reflect.DeepEqual(keys, want) {
				t.Error("retry deleted wrong keys")
			}
		}
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))
	defer api.Close()
	results, e := revokeUser(context.Background(), r, "bob", func() (*cf.KV, error) { return &cf.KV{BaseURL: api.URL}, nil }, revokeRunner{&events}, nil)
	found := false
	for _, r := range results {
		if r.Step == "subscription delete" && r.Err == nil {
			found = true
		}
	}
	if !found || deletes != 1 || e == nil {
		t.Fatal("unexpected retry result", results, deletes, e)
	}
	h, _ := os.ReadFile(filepath.Join(dir, "state/revocations.yaml"))
	if strings.Contains(string(h), tok) || (uuid != "" && strings.Contains(string(h), uuid)) {
		t.Fatal("secret in history")
	}
	history, err = loadRevocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range history {
		if len(record.PendingKVKeys) != 0 {
			t.Fatal("confirmed keys remain pending")
		}
	}
	if len(events) != 8 {
		t.Fatal("retry did not attempt both nodes and stops")
	}
	t.Log("retry deletes saved keys independently of subscription build")
}

func TestRevokeWithoutTokenOrPendingNeverConfirmsDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reg")
	if err := os.CopyFS(dir, os.DirFS("../../testdata/registry")); err != nil {
		t.Fatal(err)
	}
	r, err := registry.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	delete(r.Secrets.Users, "bob")
	r.Users[0].Formats = []string{"broken"}
	var events []string
	for i := 0; i < 2; i++ {
		results, _ := revokeUser(context.Background(), r, "bob", func() (*cf.KV, error) { return &cf.KV{}, nil }, revokeRunner{&events}, nil)
		for _, res := range results {
			if res.Step == "subscription delete" && res.Err == nil {
				t.Fatal("missing deletion targets falsely confirmed")
			}
		}
	}
}

func TestRevokeJournalFailurePreservesToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reg")
	if err := os.CopyFS(dir, os.DirFS("../../testdata/registry")); err != nil {
		t.Fatal(err)
	}
	r, err := registry.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	token := r.Secrets.Users["bob"].Token
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	var events []string
	_, err = revokeUser(context.Background(), r, "bob", func() (*cf.KV, error) { t.Fatal("KV attempted before journal"); return nil, nil }, revokeRunner{&events}, nil)
	if err == nil || r.Secrets.Users["bob"].Token != token {
		t.Fatal("lost token before journal persisted")
	}
	persisted, err := registry.Load(dir)
	if err != nil || persisted.Secrets.Users["bob"].Token != token {
		t.Fatal("persisted token lost")
	}
}
