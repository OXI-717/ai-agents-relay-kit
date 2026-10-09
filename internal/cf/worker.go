package cf

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// WorkerSecrets writes Worker secrets via the Cloudflare API (spec §6.2: one
// HMAC key per server, stored as Worker secrets INGEST_HMAC_<SERVER>).
type WorkerSecrets struct {
	Account, Script, Token, BaseURL string
	HTTP                            *http.Client
}

// SecretName converts a server id to its env name: "kz-1" → "INGEST_HMAC_KZ_1".
func SecretName(serverID string) string {
	return "INGEST_HMAC_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(serverID))
}

func (w *WorkerSecrets) base() string {
	b := w.BaseURL
	if b == "" {
		b = "https://api.cloudflare.com/client/v4"
	}
	return fmt.Sprintf("%s/accounts/%s/workers/scripts/%s/secrets", b, w.Account, w.Script)
}

// Put upserts one secret_text secret.
func (w *WorkerSecrets) Put(ctx context.Context, name, value string) error {
	kv := KV{Account: w.Account, Token: w.Token, BaseURL: w.BaseURL, HTTP: w.HTTP}
	_, err := kv.do(ctx, "PUT", w.base(), map[string]string{
		"name": name, "type": "secret_text", "text": value,
	})
	return err
}
