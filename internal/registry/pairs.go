package registry

func PairKey(user, entry string, exit ...string) string {
	key := user + "@" + entry
	if len(exit) > 0 && exit[0] != "" {
		key += "/" + exit[0]
	}
	return key
}

func ServiceKey(relay, exit string) string { return "svc:" + relay + ">" + exit }

type Pair struct {
	Key   string
	Entry Server
	Exit  Server
}

func (r *Registry) PairsFor(u User) []Pair {
	var out []Pair
	for _, s := range r.EntriesFor(u) {
		if s.Kind == "exit" {
			out = append(out, Pair{PairKey(u.ID, s.ID), s, s})
			continue
		}
		for _, id := range s.Exits {
			if e, ok := r.ServerByID(id); ok && e.Enabled && e.Kind == "exit" {
				out = append(out, Pair{PairKey(u.ID, s.ID, id), s, e})
			}
		}
	}
	return out
}

func (r *Registry) ServicePairs() []Pair {
	var out []Pair
	for _, s := range r.Servers {
		if !s.Enabled || s.Kind != "relay" {
			continue
		}
		for _, id := range s.Exits {
			if e, ok := r.ServerByID(id); ok && e.Enabled && e.Kind == "exit" {
				out = append(out, Pair{ServiceKey(s.ID, id), s, e})
			}
		}
	}
	return out
}

func (r *Registry) ServerByID(id string) (Server, bool) {
	for _, s := range r.Servers {
		if s.ID == id {
			return s, true
		}
	}
	return Server{}, false
}

func (r *Registry) ActiveUsers() []User {
	var out []User
	for _, u := range r.Users {
		if u.Status == "active" {
			out = append(out, u)
		}
	}
	return out
}

// EntriesFor returns enabled entry servers the user may connect to, in servers.yaml order.
func (r *Registry) EntriesFor(u User) []Server {
	allow := map[string]bool{}
	for _, id := range u.Entries {
		allow[id] = true
	}
	var out []Server
	for _, s := range r.Servers {
		if !s.Enabled || (s.Kind != "exit" && s.Kind != "relay") {
			continue
		}
		if len(u.Entries) == 0 || allow[s.ID] {
			out = append(out, s)
		}
	}
	return out
}

func (r *Registry) ExternalFor(u User) []External {
	var out []External
	for _, e := range r.External {
		for _, id := range e.ShareWith {
			if id == u.ID {
				out = append(out, e)
			}
		}
	}
	return out
}
