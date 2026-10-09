// Package external parses third-party server links for the registry.
package external

import (
	"fmt"
	"regexp"
	"strings"
)

type Parsed struct {
	ID, Label, Link, Host string
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func ParseLinks(text string) ([]Parsed, error) {
	var out []Parsed
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "vless://") {
			continue
		}
		u, err := ParseEndpoint(line)
		if err != nil {
			return nil, fmt.Errorf("invalid external link at line %d", i+1)
		}
		label := u.Fragment
		if label == "" {
			label = u.Hostname()
		}
		id := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(label), "-"), "-")
		if id == "" {
			id = "ext-" + strings.ReplaceAll(u.Hostname(), ".", "-")
		}
		if !slugFormat.MatchString(id) || seen[id] {
			return nil, fmt.Errorf("invalid or duplicate external id at line %d", i+1)
		}
		seen[id] = true
		out = append(out, Parsed{ID: id, Label: label, Link: line, Host: u.Hostname()})
	}
	return out, nil
}
