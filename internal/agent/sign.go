package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// Sign builds the /ingest headers per spec §6.2:
// HMAC-SHA256 over "POST\n/ingest\n<server>\n<ts>\n<batch_id>\n<sha256(body)>".
func Sign(keyHex, server string, ts int64, batchID string, body []byte) (map[string]string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) < 16 {
		return nil, fmt.Errorf("bad hmac key")
	}
	sum := sha256.Sum256(body)
	canon := "POST\n/ingest\n" + server + "\n" + strconv.FormatInt(ts, 10) + "\n" + batchID + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canon))
	return map[string]string{
		"X-VPN-Server":    server,
		"X-VPN-Timestamp": strconv.FormatInt(ts, 10),
		"X-VPN-Batch":     batchID,
		"X-VPN-Signature": hex.EncodeToString(mac.Sum(nil)),
	}, nil
}
