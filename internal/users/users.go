// Package users mutates the registry: users, their UUIDs, server keys.
package users

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OXI-717/ai-agents-relay-kit/internal/gen"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func newUUID(r *registry.Registry) string {
	used := map[string]bool{}
	for _, v := range r.Secrets.UUIDs {
		used[v] = true
	}
	for _, v := range r.Secrets.RevokedUUIDs {
		used[v] = true
	}
	for {
		if id := gen.UUID(); !used[id] {
			return id
		}
	}
}

func Add(r *registry.Registry, id, name string) error {
	for _, u := range r.Users {
		if u.ID == id {
			return fmt.Errorf("user %s already exists (status %s)", id, u.Status)
		}
	}
	tok, err := gen.Token()
	if err != nil {
		return err
	}
	r.Users = append(r.Users, registry.User{ID: id, Name: name, Status: "active", Routing: "default-ru", Formats: []string{"incy", "happ"}})
	r.Secrets.Users[id] = registry.UserSecrets{Token: tok}
	Fill(r)
	return nil
}

func Fill(r *registry.Registry) []string {
	var added []string
	for _, u := range r.ActiveUsers() {
		for _, p := range r.PairsFor(u) {
			k := p.Key
			if r.Secrets.UUIDs[k] == "" {
				r.Secrets.UUIDs[k] = newUUID(r)
				added = append(added, k)
			}
		}
	}
	for _, p := range r.ServicePairs() {
		if r.Secrets.UUIDs[p.Key] == "" {
			r.Secrets.UUIDs[p.Key] = newUUID(r)
			added = append(added, p.Key)
		}
	}
	sort.Strings(added)
	return added
}

func Revoke(r *registry.Registry, id string) error {
	idx := -1
	for i, u := range r.Users {
		if u.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("unknown user %s", id)
	}
	r.Users[idx].Status = "revoked"
	for k, v := range r.Secrets.UUIDs {
		if strings.HasPrefix(k, id+"@") {
			r.Secrets.RevokedUUIDs = append(r.Secrets.RevokedUUIDs, v)
			delete(r.Secrets.UUIDs, k)
		}
	}
	delete(r.Secrets.Users, id)
	return nil
}

func ServerKeys(r *registry.Registry, serverID string, force bool) error {
	idx := -1
	for i, s := range r.Servers {
		if s.ID == serverID {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("unknown server %s", serverID)
	}
	if sec, ok := r.Secrets.Servers[serverID]; ok && sec.PrivateKey != "" && !force {
		return fmt.Errorf("%s already has keys; use --force to rotate", serverID)
	}
	priv, pub, err := gen.RealityKeys()
	if err != nil {
		return err
	}
	sid, err := gen.ShortID()
	if err != nil {
		return err
	}
	path, err := gen.Path()
	if err != nil {
		return err
	}
	r.Secrets.Servers[serverID] = registry.ServerSecrets{PrivateKey: priv, ShortID: sid, XHTTPPath: path}
	r.Servers[idx].Reality.PublicKey = pub
	return nil
}

// FillTokens issues subscription tokens to active users that have none; existing tokens are kept.
func FillTokens(r *registry.Registry) ([]string, error) {
	var added []string
	for _, u := range r.ActiveUsers() {
		if r.Secrets.Users[u.ID].Token != "" {
			continue
		}
		tok, err := gen.Token()
		if err != nil {
			return nil, err
		}
		r.Secrets.Users[u.ID] = registry.UserSecrets{Token: tok}
		added = append(added, u.ID)
	}
	return added, nil
}
