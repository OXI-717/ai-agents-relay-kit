package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/OXI-717/ai-agents-relay-kit/internal/cf"
	"github.com/OXI-717/ai-agents-relay-kit/internal/deploy"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type revokeRunner struct{ events *[]string }

func (f revokeRunner) Run(_ context.Context, s registry.Server, _ bool, cmd string, _ []byte) ([]byte, error) {
	*f.events = append(*f.events, "node "+s.ID)
	return nil, errors.New("offline")
}
func TestRevokeDeleteIndependentOfOtherSubscriptions(t *testing.T) {
	for _, failDelete := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete ok", true: "delete fails"}[failDelete], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "reg")
			if e := os.CopyFS(dir, os.DirFS("../../testdata/registry")); e != nil {
				t.Fatal(e)
			}
			r, e := registry.Load(dir)
			if e != nil {
				t.Fatal(e)
			}
			token := r.Secrets.Users["bob"].Token
			r.Users[0].Formats = []string{"broken"} // full subscription build must fail without blocking the revoke
			var events, deleted []string
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				events = append(events, "delete")
				if req.Method != "POST" || !strings.HasSuffix(req.URL.Path, "/bulk/delete") {
					t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
				}
				if e := json.NewDecoder(req.Body).Decode(&deleted); e != nil {
					t.Error(e)
				}
				persisted, e := registry.Load(dir)
				if e != nil || persisted.Users[1].Status != "revoked" {
					t.Error("registry not saved before deletion")
				}
				if failDelete {
					w.WriteHeader(500)
					return
				}
				w.Write([]byte(`{"success":true}`))
			}))
			defer api.Close()
			factory := func() (*cf.KV, error) { return &cf.KV{BaseURL: api.URL}, nil }
			results, e := revokeUser(context.Background(), r, "bob", factory, revokeRunner{&events}, deploy.VerifyFunc(func(context.Context, registry.Server) error { return nil }))
			if e == nil {
				t.Fatal("incomplete reported successful")
			}
			if strings.Join(events, ",") != "delete,node kz,node kz,node am,node am" {
				t.Fatalf("wrong ordering: %v", events)
			}
			if len(deleted) != 4 {
				t.Fatalf("keys: %v", deleted)
			}
			for _, k := range deleted {
				if !strings.HasPrefix(k, deploy.KVKey(token, "")) {
					t.Fatal("deleted another user's key")
				}
			}
			if deleted[3] != deploy.KVKey(token, "happ")+":routing" {
				t.Fatal("missing routing key")
			}
			found := false
			for _, res := range results {
				if res.Step == "subscriptions publish" && res.Err != nil {
					found = true
				}
			}
			if !found {
				t.Fatal("full subs failure not reported")
			}
			data, e := os.ReadFile(filepath.Join(dir, "state", "revocations.yaml"))
			if e != nil {
				t.Fatal(e)
			}
			var history []revocationRecord
			if e = yaml.Unmarshal(data, &history); e != nil {
				t.Fatal(e)
			}
			if len(history) != 1 || history[0].Nodes["kz"] != "failed" || !strings.HasSuffix(history[0].Date, "Z") {
				t.Fatalf("history: %+v", history)
			}
			if strings.Contains(string(data), token) || strings.Contains(string(data), "uuid") {
				t.Fatal("history contains secrets")
			}
			if e = appendRevocation(dir, history[0]); e != nil {
				t.Fatal(e)
			}
			data, _ = os.ReadFile(filepath.Join(dir, "state", "revocations.yaml"))
			yaml.Unmarshal(data, &history)
			if len(history) != 2 {
				t.Fatal("history overwritten")
			}
		})
	}
}
