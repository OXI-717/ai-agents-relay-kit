package external

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var uuidFormat = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hostLabel = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var slugFormat = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if !hostLabel.MatchString(part) {
			return false
		}
	}
	return true
}

// ParseEndpoint validates the authority without ever returning parser errors or input.
func ParseEndpoint(link string) (*url.URL, error) {
	invalid := fmt.Errorf("invalid external link at line 1")
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "vless" || u.User == nil {
		return nil, invalid
	}
	if !uuidFormat.MatchString(u.User.Username()) || !validHost(u.Hostname()) {
		return nil, invalid
	}
	if _, password := u.User.Password(); password {
		return nil, invalid
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, invalid
	}
	return u, nil
}
