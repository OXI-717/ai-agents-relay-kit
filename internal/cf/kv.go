// Package cf is a minimal Cloudflare Workers KV REST client.
package cf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type KV struct {
	Account, Namespace, Token, BaseURL string
	HTTP                               *http.Client
}

type Entry struct {
	Key      string            `json:"key"`
	Value    string            `json:"value"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type apiResp struct {
	Success bool                       `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage            `json:"result"`
	Info    struct{ Cursor string }    `json:"result_info"`
}

func (k *KV) base() string {
	b := k.BaseURL
	if b == "" {
		b = "https://api.cloudflare.com/client/v4"
	}
	return fmt.Sprintf("%s/accounts/%s/storage/kv/namespaces/%s", b, k.Account, k.Namespace)
}

func (k *KV) do(ctx context.Context, method, u string, body any) (apiResp, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return apiResp{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return apiResp{}, err
	}
	req.Header.Set("Authorization", "Bearer "+k.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := k.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return apiResp{}, fmt.Errorf("cloudflare %s: %v", method, err)
	}
	defer resp.Body.Close()
	var ar apiResp
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	if resp.StatusCode >= 300 || !ar.Success {
		msg := resp.Status
		if len(ar.Errors) > 0 {
			msg += ": " + ar.Errors[0].Message
		}
		return ar, fmt.Errorf("cloudflare %s %s", method, msg)
	}
	return ar, nil
}

func (k *KV) BulkPut(ctx context.Context, entries []Entry) error {
	if entries == nil {
		entries = []Entry{}
	}
	_, err := k.do(ctx, "PUT", k.base()+"/bulk", entries)
	return err
}

func (k *KV) BulkDelete(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := k.do(ctx, "POST", k.base()+"/bulk/delete", keys)
	return err
}

func (k *KV) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	cursor := ""
	for {
		q := url.Values{"prefix": {prefix}, "limit": {"1000"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		ar, err := k.do(ctx, "GET", k.base()+"/keys?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var items []struct{ Name string }
		if err := json.Unmarshal(ar.Result, &items); err != nil {
			return nil, err
		}
		for _, it := range items {
			out = append(out, it.Name)
		}
		if ar.Info.Cursor == "" {
			return out, nil
		}
		cursor = ar.Info.Cursor
	}
}
