package deploy

import (
	"encoding/json"

	"github.com/OXI-717/ai-agents-relay-kit/internal/cf"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

// Catalog is the KV document the worker admin reads: servers and users without
// any secrets, keyed by the same user_ref the agent reports (spec §6.5).
func Catalog(r *registry.Registry, generatedAt int64) cf.Entry {
	type srv struct {
		ID       string `json:"id"`
		Label    string `json:"label"`
		Kind     string `json:"kind"`
		Enabled  bool   `json:"enabled"`
		Location string `json:"location"`
	}
	type usr struct {
		Ref    string `json:"ref"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	doc := struct {
		SchemaVersion int    `json:"schema_version"`
		GeneratedAt   int64  `json:"generated_at"`
		Servers       []srv  `json:"servers"`
		Users         []usr  `json:"users"`
	}{SchemaVersion: 1, GeneratedAt: generatedAt}
	for _, s := range r.Servers {
		doc.Servers = append(doc.Servers, srv{s.ID, s.Label, s.Kind, s.Enabled, s.Location})
	}
	for _, u := range r.Users {
		doc.Users = append(doc.Users, usr{registry.UserRef(u.ID), u.Name, u.Status})
	}
	b, _ := json.Marshal(doc)
	return cf.Entry{Key: "catalog", Value: string(b)}
}
