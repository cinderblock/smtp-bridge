// Package config defines the on-disk configuration schema for the SMTP→HTTP
// bridge and the logic to load and validate it.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a Go duration string
// (e.g. "30s", "5m") in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the root configuration object.
type Config struct {
	Listeners       []Listener `yaml:"listeners"`
	Hostname        string     `yaml:"hostname"`
	MaxMessageBytes int64      `yaml:"max_message_bytes"`
	ReadTimeout     Duration   `yaml:"read_timeout"`
	WriteTimeout    Duration   `yaml:"write_timeout"`

	TLS      TLS      `yaml:"tls"`
	Auth     Auth     `yaml:"auth"`
	Logging  Logging  `yaml:"logging"`
	Web      Web      `yaml:"web"`
	Delivery Delivery `yaml:"delivery"`
	Routes   []Route  `yaml:"routes"`
}

// Web configures the optional, UNAUTHENTICATED status web UI (view + delete
// captured messages; it does not edit config). Bind it only to loopback (or
// publish it loopback-only) — it has no access control.
type Web struct {
	Listen string `yaml:"listen"` // host:port, e.g. "127.0.0.1:8025"; empty = disabled
}

// Enabled reports whether the web UI should run.
func (w Web) Enabled() bool { return w.Listen != "" }

// TLSMode is a per-listener transport-security mode.
type TLSMode string

const (
	// TLSModeNone: plaintext only; STARTTLS not advertised. AUTH travels in the
	// clear (only sensible on a trusted network).
	TLSModeNone TLSMode = "none"
	// TLSModeStartTLS: plaintext connection that advertises STARTTLS; clients
	// upgrade in place (ports 587/25/2525).
	TLSModeStartTLS TLSMode = "starttls"
	// TLSModeImplicit: TLS from the first byte, a.k.a. SMTPS (port 465).
	TLSModeImplicit TLSMode = "implicit"
)

// Listener is a single bound SMTP port with its own transport-security mode.
type Listener struct {
	Address string  `yaml:"address"` // e.g. ":587"
	TLS     TLSMode `yaml:"tls"`     // none | starttls | implicit
	// InsecureAuth permits AUTH on a non-TLS connection for a starttls listener
	// (i.e. AUTH without first issuing STARTTLS). Default false: AUTH requires
	// TLS. Ignored for implicit (always TLS) and none (always insecure).
	InsecureAuth bool `yaml:"insecure_auth"`
}

// NeedsCert reports whether this listener requires a server certificate.
func (l Listener) NeedsCert() bool {
	return l.TLS == TLSModeStartTLS || l.TLS == TLSModeImplicit
}

// CertMode selects where the server certificate comes from.
type CertMode string

const (
	CertModeNone  CertMode = "none"  // no certificate; only `none` listeners allowed
	CertModeFiles CertMode = "files" // load cert_file/key_file
	CertModeAuto  CertMode = "auto"  // obtain + auto-renew via ACME DNS-01 (certmagic)
)

// TLS configures the server certificate shared by all TLS-enabled listeners.
type TLS struct {
	Mode CertMode `yaml:"mode"`

	// Mode == files
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// Mode == auto (ACME DNS-01)
	Hostnames   []string `yaml:"hostnames"`    // certificate names, e.g. [smtp.example.com]
	ACMEEmail   string   `yaml:"acme_email"`   // ACME account contact
	DNSProvider string   `yaml:"dns_provider"` // currently only "cloudflare"
	CFAPIToken  string   `yaml:"cf_api_token"` // Cloudflare token; falls back to $CLOUDFLARE_API_TOKEN
	CADirURL    string   `yaml:"ca_dir_url"`   // optional ACME directory override (e.g. LE staging)
	StoragePath string   `yaml:"storage_path"` // where obtained certs are cached (MUST persist)
}

// Auth holds network-level access control. SMTP credentials are per-route
// (see Route) — a sender authenticates as a route.
type Auth struct {
	AllowIPs []string `yaml:"allow_ips"` // optional CIDR allowlist, applied on top of AUTH
}

// Logging controls the optional (opt-out) message log.
type Logging struct {
	Enabled  bool   `yaml:"enabled"`
	Database string `yaml:"database"`
	// Rejections persists refused requests (envelope metadata only) for
	// debugging. Defaults to true; set to false to disable. Pointer so an
	// unset value is distinguishable from an explicit false.
	Rejections *bool `yaml:"log_rejections"`
	// RejectionRetentionDays auto-deletes rejections older than this many days.
	// 0 (default) keeps them forever.
	RejectionRetentionDays int `yaml:"rejection_retention_days"`
}

// LogRejections reports whether rejection logging is enabled (default true).
func (l Logging) LogRejections() bool { return l.Rejections == nil || *l.Rejections }

// Mode is the webhook delivery model.
type Mode string

const (
	ModeAsync Mode = "async" // accept, enqueue, deliver in background with retries
	ModeSync  Mode = "sync"  // deliver inline; only 250-OK if webhook returns 2xx
)

// Delivery holds global delivery defaults; routes may override Mode.
type Delivery struct {
	DefaultMode  Mode     `yaml:"default_mode"`
	Timeout      Duration `yaml:"timeout"`
	MaxRetries   int      `yaml:"max_retries"`
	RetryBackoff Duration `yaml:"retry_backoff"`
	Concurrency  int      `yaml:"concurrency"`
}

// Route bundles a per-route SMTP AUTH credential, a recipient match, and an
// optional webhook. A sender authenticates as the route's user and may deliver
// only to routes that credential owns (and whose recipient match passes).
type Route struct {
	Name string `yaml:"name"`

	// Per-route credential. A sender authenticates as this route; provide
	// exactly one of Password or PasswordBcrypt.
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	PasswordBcrypt string `yaml:"password_bcrypt"`

	Match   Match        `yaml:"match"`
	Webhook Webhook      `yaml:"webhook"` // optional: empty url = capture-only
	Mode    Mode         `yaml:"mode"`    // "" = use Delivery.DefaultMode
	Include IncludeRules `yaml:"include"`
}

// HasWebhook reports whether the route forwards to a webhook. A route with no
// webhook URL is capture-only: matching mail is accepted and logged but not
// delivered anywhere (until an endpoint is configured).
func (r Route) HasWebhook() bool { return r.Webhook.URL != "" }

// Match holds recipient conditions. Every non-empty field must match (AND).
// A route with an empty Match matches every recipient (catch-all).
type Match struct {
	Rcpt          string `yaml:"rcpt"`           // exact address, case-insensitive
	RcptDomain    string `yaml:"rcpt_domain"`    // domain part
	RcptLocalpart string `yaml:"rcpt_localpart"` // local part, before any +tag
}

// Webhook is the HTTP target.
type Webhook struct {
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"` // default POST
	Secret  string            `yaml:"secret"` // HMAC-SHA256 signing key; "" disables signing
	Headers map[string]string `yaml:"headers"`
}

// IncludeRules control payload contents.
type IncludeRules struct {
	Raw                bool  `yaml:"raw"`                  // include base64 raw .eml
	Attachments        bool  `yaml:"attachments"`          // include attachment bodies
	MaxAttachmentBytes int64 `yaml:"max_attachment_bytes"` // 0 = unlimited
}

// EffectiveMode resolves the route's delivery mode against the global default.
func (r Route) EffectiveMode(def Mode) Mode {
	if r.Mode != "" {
		return r.Mode
	}
	if def != "" {
		return def
	}
	return ModeAsync
}

// Load reads, parses, applies defaults to, and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.Prepare(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Prepare applies defaults and validates an in-memory config. Load calls this
// after decoding; construct-in-code callers (e.g. tests) can call it directly.
func (c *Config) Prepare() error {
	c.applyDefaults()
	return c.Validate()
}

func (c *Config) applyDefaults() {
	if len(c.Listeners) == 0 {
		c.Listeners = []Listener{{Address: ":2525", TLS: TLSModeNone}}
	}
	for i := range c.Listeners {
		if c.Listeners[i].TLS == "" {
			c.Listeners[i].TLS = TLSModeNone
		}
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = CertModeNone
	}
	if c.TLS.Mode == CertModeAuto {
		if c.TLS.DNSProvider == "" {
			c.TLS.DNSProvider = "cloudflare"
		}
		if c.TLS.StoragePath == "" {
			c.TLS.StoragePath = "./certs"
		}
	}
	if c.Hostname == "" {
		c.Hostname = "localhost"
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = 25 * 1024 * 1024
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = Duration(60 * time.Second)
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = Duration(60 * time.Second)
	}
	if c.Delivery.DefaultMode == "" {
		c.Delivery.DefaultMode = ModeAsync
	}
	if c.Delivery.Timeout == 0 {
		c.Delivery.Timeout = Duration(30 * time.Second)
	}
	if c.Delivery.MaxRetries == 0 {
		c.Delivery.MaxRetries = 5
	}
	if c.Delivery.RetryBackoff == 0 {
		c.Delivery.RetryBackoff = Duration(10 * time.Second)
	}
	if c.Delivery.Concurrency == 0 {
		c.Delivery.Concurrency = 4
	}
	// The database is always needed for the durable async delivery queue; the
	// Logging.Enabled flag only controls whether message *content* is persisted.
	if c.Logging.Database == "" {
		c.Logging.Database = "./smtp-bridge.db"
	}
	for i := range c.Routes {
		if c.Routes[i].Webhook.Method == "" {
			c.Routes[i].Webhook.Method = "POST"
		}
	}
}

// needsCert reports whether any listener requires a server certificate.
func (c *Config) needsCert() bool {
	for _, l := range c.Listeners {
		if l.NeedsCert() {
			return true
		}
	}
	return false
}

// validateTLS checks listeners and the certificate source are mutually consistent.
func (c *Config) validateTLS() error {
	for i, l := range c.Listeners {
		if l.Address == "" {
			return fmt.Errorf("listeners[%d]: address is required", i)
		}
		switch l.TLS {
		case TLSModeNone, TLSModeStartTLS, TLSModeImplicit:
		default:
			return fmt.Errorf("listeners[%q]: invalid tls %q (want none, starttls, or implicit)", l.Address, l.TLS)
		}
	}
	needCert := c.needsCert()
	switch c.TLS.Mode {
	case CertModeNone:
		if needCert {
			return fmt.Errorf("a listener uses starttls/implicit but tls.mode is none — set tls.mode to files or auto")
		}
	case CertModeFiles:
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.mode is files but tls.cert_file/key_file are not set")
		}
	case CertModeAuto:
		if len(c.TLS.Hostnames) == 0 {
			return fmt.Errorf("tls.mode is auto but tls.hostnames is empty")
		}
		if c.TLS.DNSProvider != "cloudflare" {
			return fmt.Errorf("tls.dns_provider %q unsupported (only cloudflare)", c.TLS.DNSProvider)
		}
		if c.TLS.CFAPIToken == "" && os.Getenv("CLOUDFLARE_API_TOKEN") == "" {
			return fmt.Errorf("tls.mode is auto with cloudflare but no token (set tls.cf_api_token or $CLOUDFLARE_API_TOKEN)")
		}
	default:
		return fmt.Errorf("tls.mode %q invalid (want none, files, or auto)", c.TLS.Mode)
	}
	return nil
}

// Validate checks for a usable configuration.
func (c *Config) Validate() error {
	for _, cidr := range c.Auth.AllowIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("auth.allow_ips: %q is not a valid CIDR: %w", cidr, err)
		}
	}
	if err := c.validateTLS(); err != nil {
		return err
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("routes: at least one route is required")
	}
	seen := map[string]bool{}
	creds := map[string]string{} // username -> credential, to catch conflicts
	for i, r := range c.Routes {
		if r.Name == "" {
			return fmt.Errorf("routes[%d]: name is required", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("routes: duplicate name %q", r.Name)
		}
		seen[r.Name] = true

		// Per-route credential (AUTH is mandatory).
		if r.Username == "" {
			return fmt.Errorf("routes[%q]: username is required", r.Name)
		}
		if r.Password == "" && r.PasswordBcrypt == "" {
			return fmt.Errorf("routes[%q]: set password or password_bcrypt", r.Name)
		}
		if r.Password != "" && r.PasswordBcrypt != "" {
			return fmt.Errorf("routes[%q]: set only one of password or password_bcrypt", r.Name)
		}
		// A username may own several routes, but its credential must be identical.
		cred := r.Password + "\x00" + r.PasswordBcrypt
		if prev, ok := creds[r.Username]; ok && prev != cred {
			return fmt.Errorf("routes: username %q has conflicting passwords across routes", r.Username)
		}
		creds[r.Username] = cred

		// Webhook is optional; an empty url = capture-only. Such mail must be
		// storable, else it would be accepted and silently dropped.
		if !r.HasWebhook() && !c.Logging.Enabled {
			return fmt.Errorf("routes[%q]: capture-only route (no webhook.url) requires logging.enabled=true", r.Name)
		}
		switch r.EffectiveMode(c.Delivery.DefaultMode) {
		case ModeAsync, ModeSync:
		default:
			return fmt.Errorf("routes[%q]: invalid mode %q (want async or sync)", r.Name, r.Mode)
		}
	}
	return nil
}
