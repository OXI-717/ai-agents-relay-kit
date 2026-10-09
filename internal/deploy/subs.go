package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/OXI-717/ai-agents-relay-kit/internal/build"
	"github.com/OXI-717/ai-agents-relay-kit/internal/cf"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func KVKey(token, format string) string {
	h := sha256.Sum256([]byte(token))
	return "sub:" + hex.EncodeToString(h[:]) + ":" + format
}

func PlanKV(r *registry.Registry, updated int64) ([]cf.Entry, map[string]bool, error) {
	var put []cf.Entry
	keep := map[string]bool{}
	title := "base64:" + base64.StdEncoding.EncodeToString([]byte(r.Cloudflare.Title))
	for _, u := range r.ActiveUsers() {
		tok := r.Secrets.Users[u.ID].Token
		for _, f := range u.Formats {
			var body []byte
			var err error
			switch f {
			case "incy":
				body, err = build.IncySubscription(r, u, updated)
			case "happ":
				body, err = build.HappSubscription(r, u)
			default:
				err = fmt.Errorf("unknown format %s", f)
			}
			if err != nil {
				return nil, nil, fmt.Errorf("%s/%s: %w", u.ID, f, err)
			}
			ct := "text/plain; charset=utf-8"
			if f == "happ" || f == "incy" {
				// Оба формата теперь отдают JSON-массив полных конфигов.
				ct = "application/json"
			}
			k := KVKey(tok, f)
			put = append(put, cf.Entry{Key: k, Value: string(body), Metadata: map[string]string{
				"format": f, "title": title, "content_type": ct, "update_interval": "12",
			}})
			keep[k] = true
			// Routing для happ и incy идёт заголовком воркера: JSON-тело не может
			// нести строку incy://routing (docs.incy.cc: headers take precedence).
			if f == "happ" || f == "incy" {
				var link string
				var err error
				if f == "happ" {
					link, err = build.HappRoutingLink(r, u, updated)
				} else {
					link, err = build.IncyRoutingLink(r, u, updated)
				}
				if err != nil {
					return nil, nil, fmt.Errorf("%s/%s routing: %w", u.ID, f, err)
				}
				put = append(put, cf.Entry{Key: k + ":routing", Value: link})
				keep[k+":routing"] = true
			}
		}
	}
	return put, keep, nil
}

func Subs(ctx context.Context, r *registry.Registry, kv *cf.KV, updated int64) (int, int, error) {
	put, keep, err := PlanKV(r, updated)
	if err != nil {
		return 0, 0, err
	}
	if err := kv.BulkPut(ctx, put); err != nil {
		return 0, 0, err
	}
	existing, err := kv.ListKeys(ctx, "sub:")
	if err != nil {
		return len(put), 0, err
	}
	var del []string
	for _, k := range existing {
		if !keep[k] {
			del = append(del, k)
		}
	}
	return len(put), len(del), kv.BulkDelete(ctx, del)
}
