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
	Listen          string   `yaml:"listen"`
	Hostname        string   `yaml:"hostname"`
	MaxMessageBytes int64    `yaml:"max_message_bytes"`
	ReadTimeout     Duration `yaml:"read_timeout"`
	WriteTimeout    Duration `yaml:"write_timeout"`

	TLS      TLS      `yaml:"tls"`
	Auth     Auth     `yaml:"auth"`
	Logging  Logging  `yaml:"logging"`
	Delivery Delivery `yaml:"delivery"`
	Routes   []Route  `yaml:"routes"`
}

// TLS configures STARTTLS. When CertFile/KeyFile are empty, STARTTLS is disabled.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Required forces clients to issue STARTTLS before AUTH/MAIL.
	Required bool `yaml:"required"`
}

func (t TLS) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// Auth controls who may submit mail.
type Auth struct {
	Users    []User   `yaml:"users"`
	AllowIPs []string `yaml:"allow_ips"` // optional CIDR allowlist, applied on top of AUTH
}

// User is a single SMTP AUTH credential. Provide exactly one of Password or
// PasswordBcrypt.
type User struct {
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	PasswordBcrypt string `yaml:"password_bcrypt"`
}

// Logging controls the optional (opt-out) message log.
type Logging struct {
	Enabled  bool   `yaml:"enabled"`
	Database string `yaml:"database"`
	// Rejections persists refused requests (envelope metadata only) for
	// debugging. Defaults to true; set to false to disable. Pointer so an
	// unset value is distinguishable from an explicit false.
	Rejections *bool `yaml:"log_rejections"`
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

// Route maps matching recipients to a webhook.
type Route struct {
	Name    string       `yaml:"name"`
	Match   Match        `yaml:"match"`
	Webhook Webhook      `yaml:"webhook"`
	Mode    Mode         `yaml:"mode"` // "" = use Delivery.DefaultMode
	Include IncludeRules `yaml:"include"`
}

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
	if c.Listen == "" {
		c.Listen = ":2525"
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

// Validate checks for a usable configuration.
func (c *Config) Validate() error {
	if len(c.Auth.Users) == 0 {
		return fmt.Errorf("auth.users: at least one user is required (AUTH is mandatory)")
	}
	names := map[string]bool{}
	for i, u := range c.Auth.Users {
		if u.Username == "" {
			return fmt.Errorf("auth.users[%d]: username is required", i)
		}
		if u.Password == "" && u.PasswordBcrypt == "" {
			return fmt.Errorf("auth.users[%q]: set password or password_bcrypt", u.Username)
		}
		if u.Password != "" && u.PasswordBcrypt != "" {
			return fmt.Errorf("auth.users[%q]: set only one of password or password_bcrypt", u.Username)
		}
		if names[u.Username] {
			return fmt.Errorf("auth.users: duplicate username %q", u.Username)
		}
		names[u.Username] = true
	}
	for _, cidr := range c.Auth.AllowIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("auth.allow_ips: %q is not a valid CIDR: %w", cidr, err)
		}
	}
	if c.TLS.Required && !c.TLS.Enabled() {
		return fmt.Errorf("tls.required is set but tls.cert_file/key_file are not configured")
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("routes: at least one route is required")
	}
	seen := map[string]bool{}
	for i, r := range c.Routes {
		if r.Name == "" {
			return fmt.Errorf("routes[%d]: name is required", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("routes: duplicate name %q", r.Name)
		}
		seen[r.Name] = true
		if r.Webhook.URL == "" {
			return fmt.Errorf("routes[%q]: webhook.url is required", r.Name)
		}
		switch r.EffectiveMode(c.Delivery.DefaultMode) {
		case ModeAsync, ModeSync:
		default:
			return fmt.Errorf("routes[%q]: invalid mode %q (want async or sync)", r.Name, r.Mode)
		}
	}
	return nil
}
