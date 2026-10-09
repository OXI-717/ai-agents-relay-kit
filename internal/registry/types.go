// Package registry is the single source of truth: servers, users, external servers, routing.
package registry

type Registry struct {
	Servers    []Server
	Users      []User
	External   []External
	Routing    []RoutingProfile
	Transport  Transport
	Pins       Pins
	Cloudflare Cloudflare
	Secrets    Secrets
	Dir        string
}

type Server struct {
	ID       string   `yaml:"id"`
	Label    string   `yaml:"label"` // короткое имя в клиенте: "KZ", "AM"
	Enabled  bool     `yaml:"enabled"`
	Kind     string   `yaml:"kind"` // exit | relay
	Provider string   `yaml:"provider"`
	Location string   `yaml:"location"`
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	SSH      SSH      `yaml:"ssh"`
	Reality  Reality  `yaml:"reality"`
	Exits    []string `yaml:"exits,omitempty"`
}

type SSH struct {
	User string `yaml:"user"`
	Key  string `yaml:"key"`
	// BootstrapUser runs root-level bootstrap via sudo when root SSH is unavailable.
	BootstrapUser string `yaml:"bootstrap_user,omitempty"`
	// BootstrapKey is the identity for root-level bootstrap; default ~/.ssh/id_rsa.
	BootstrapKey string `yaml:"bootstrap_key,omitempty"`
}

type Reality struct {
	Target      string   `yaml:"target"`
	ServerNames []string `yaml:"server_names"`
	PublicKey   string   `yaml:"public_key"`
}

type User struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	Admin   bool     `yaml:"admin,omitempty"`
	Status  string   `yaml:"status"` // active | revoked
	Routing string   `yaml:"routing"`
	Entries []string `yaml:"entries,omitempty"` // пусто = все включённые серверы
	Formats []string `yaml:"formats"`
}

type External struct {
	ID        string   `yaml:"id"`
	Label     string   `yaml:"label"`
	Owner     string   `yaml:"owner"`
	ShareWith []string `yaml:"share_with"`
	Probe     bool     `yaml:"probe"`
}

type RoutingProfile struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	DirectSites []string `yaml:"direct_sites"`
	DirectIP    []string `yaml:"direct_ip"`
	ProxySites  []string `yaml:"proxy_sites"`
	ProxyIP     []string `yaml:"proxy_ip"`
}

type Transport struct {
	ClientMode string            `yaml:"client_mode"` // stream-one
	ServerMode string            `yaml:"server_mode"` // auto
	Xmux       map[string]any    `yaml:"xmux"`
	Fragment   map[string]string `yaml:"fragment"`
	DNS        []string          `yaml:"dns"`
}

type Pins struct {
	ServerImage     string `yaml:"server_image"` // ghcr.io/xtls/xray-core@sha256:…
	LocalXrayURL    string `yaml:"local_xray_url"`
	LocalXraySHA256 string `yaml:"local_xray_sha256"`
	GeoipURL        string `yaml:"geoip_url"` // закреплённый release asset, не latest
	GeoipSHA256     string `yaml:"geoip_sha256"`
	GeositeURL      string `yaml:"geosite_url"`
	GeositeSHA256   string `yaml:"geosite_sha256"`
}

type Cloudflare struct {
	AccountID     string `yaml:"account_id"`
	KVNamespaceID string `yaml:"kv_namespace_id"`
	SubBaseURL    string `yaml:"sub_base_url"` // например: https://sub.example.com
	Title         string `yaml:"title"`
}

type Secrets struct {
	Servers      map[string]ServerSecrets `yaml:"servers"`
	Users        map[string]UserSecrets   `yaml:"users"`
	UUIDs        map[string]string        `yaml:"uuids"` // PairKey → UUID
	RevokedUUIDs []string                 `yaml:"revoked_uuids"`
	External     map[string]string        `yaml:"external"` // id → vless link
}

type ServerSecrets struct {
	PrivateKey string `yaml:"private_key"`
	ShortID    string `yaml:"short_id"`
	XHTTPPath  string `yaml:"xhttp_path"`
}

type UserSecrets struct {
	Token string `yaml:"token"`
}
