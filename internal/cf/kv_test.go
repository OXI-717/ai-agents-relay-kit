package cf

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBulkPutAndList(t *testing.T) {
	var gotPut []Entry
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/bulk"):
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotPut)
			w.Write([]byte(`{"success":true,"result":{}}`))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/keys"):
			w.Write([]byte(`{"success":true,"result":[{"name":"sub:x:incy"}],"result_info":{"cursor":""}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	kv := &KV{Account: "a", Namespace: "n", Token: "tok", BaseURL: srv.URL, HTTP: srv.Client()}
	if err := kv.BulkPut(context.Background(), []Entry{{Key: "k", Value: "v", Metadata: map[string]string{"format": "incy"}}}); err != nil {
		t.Fatal(err)
	}
	if len(gotPut) != 1 || gotPut[0].Key != "k" {
		t.Fatalf("put %v", gotPut)
	}
	keys, err := kv.ListKeys(context.Background(), "sub:")
	if err != nil || len(keys) != 1 || keys[0] != "sub:x:incy" {
		t.Fatalf("keys %v %v", keys, err)
	}
}

func TestErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"success":false,"errors":[{"message":"Authentication error"}]}`))
	}))
	defer srv.Close()
	kv := &KV{Account: "a", Namespace: "n", Token: "supersecrettoken123", BaseURL: srv.URL, HTTP: srv.Client()}
	err := kv.BulkPut(context.Background(), nil)
	if err == nil || strings.Contains(err.Error(), "supersecrettoken123") || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("err %v", err)
	}
}
