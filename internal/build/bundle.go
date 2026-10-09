package build

import (
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

// Bundle is the offline fallback: plain links + QR of the first link, sent via Telegram.
func Bundle(r *registry.Registry, u registry.User) ([]byte, []byte, error) {
	ps, err := Profiles(r, u)
	if err != nil {
		return nil, nil, err
	}
	if len(ps) == 0 {
		return nil, nil, fmt.Errorf("%s: no entries", u.ID)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Аварийный доступ VPN для %s. Добавь ссылки в INCY: «+» → «Из буфера».\n\n", u.Name)
	for _, p := range ps {
		b.WriteString(VlessLink(r, p) + "\n\n")
	}
	png, err := qrcode.Encode(VlessLink(r, ps[0]), qrcode.Medium, 512)
	if err != nil {
		return nil, nil, err
	}
	return []byte(b.String()), png, nil
}
