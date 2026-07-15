// Package server implements the SMTP frontend: it accepts authenticated
// submissions, routes each recipient to a webhook, and hands messages to the
// delivery layer.
package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"

	"github.com/cinderblock/smtp-bridge/internal/config"
	"github.com/cinderblock/smtp-bridge/internal/delivery"
	"github.com/cinderblock/smtp-bridge/internal/mail"
	"github.com/cinderblock/smtp-bridge/internal/router"
	"github.com/cinderblock/smtp-bridge/internal/store"
)

// credential is a resolved per-route SMTP AUTH credential.
type credential struct {
	password       string
	passwordBcrypt string
}

// Backend implements smtp.Backend.
type Backend struct {
	cfg       *config.Config
	router    *router.Router
	deliverer *delivery.Deliverer
	store     *store.Store
	log       *slog.Logger
	users     map[string]credential // username -> credential, derived from routes
	allowNets []*net.IPNet
	newID     func() string
}

// Server runs the SMTP backend across one or more listeners (each with its own
// TLS mode), all sharing a single authentication/routing backend.
type Server struct {
	be        *Backend
	tlsConfig *tls.Config
	log       *slog.Logger
	servers   []*smtp.Server
	lns       []net.Listener
}

// New builds the multi-listener server. tlsConfig is the shared certificate
// source (from internal/tlsconf); it may be nil only if every listener is plain.
func New(cfg *config.Config, rt *router.Router, d *delivery.Deliverer, st *store.Store, log *slog.Logger, newID func() string, tlsConfig *tls.Config) (*Server, error) {
	// Credentials are per-route; a username may own several routes (config
	// validation guarantees a consistent password across them).
	users := make(map[string]credential, len(cfg.Routes))
	for _, r := range cfg.Routes {
		users[r.Username] = credential{password: r.Password, passwordBcrypt: r.PasswordBcrypt}
	}
	var nets []*net.IPNet
	for _, cidr := range cfg.Auth.AllowIPs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}

	be := &Backend{
		cfg: cfg, router: rt, deliverer: d, store: st, log: log,
		users: users, allowNets: nets, newID: newID,
	}
	return &Server{be: be, tlsConfig: tlsConfig, log: log}, nil
}

// newSMTPServer builds a go-smtp server for one listener sharing the backend.
func (s *Server) newSMTPServer(l config.Listener) *smtp.Server {
	cfg := s.be.cfg
	srv := smtp.NewServer(s.be)
	srv.Domain = cfg.Hostname
	srv.ReadTimeout = cfg.ReadTimeout.D()
	srv.WriteTimeout = cfg.WriteTimeout.D()
	srv.MaxMessageBytes = cfg.MaxMessageBytes
	srv.MaxRecipients = 100

	switch l.TLS {
	case config.TLSModeStartTLS:
		srv.TLSConfig = s.tlsConfig
		// AUTH requires STARTTLS first unless the listener opts into insecure AUTH.
		srv.AllowInsecureAuth = l.InsecureAuth
	case config.TLSModeImplicit:
		srv.TLSConfig = s.tlsConfig
		// The connection is already TLS (wrapped listener), so AUTH is secure.
		srv.AllowInsecureAuth = false
	default: // TLSModeNone
		srv.AllowInsecureAuth = true // no TLS available; AUTH must be permitted plaintext
	}
	return srv
}

// Serve binds and starts every configured listener. It returns once all are
// bound (or on the first bind error); each listener is then served in its own
// goroutine until Close.
func (s *Server) Serve() error {
	for _, l := range s.be.cfg.Listeners {
		ln, err := net.Listen("tcp", l.Address)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen %s: %w", l.Address, err)
		}
		if l.TLS == config.TLSModeImplicit {
			ln = tls.NewListener(ln, s.tlsConfig)
		}
		srv := s.newSMTPServer(l)
		s.servers = append(s.servers, srv)
		s.lns = append(s.lns, ln)
		s.log.Info("listening", "address", ln.Addr().String(), "tls", string(l.TLS))
		go func(srv *smtp.Server, ln net.Listener, addr string) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
				s.log.Error("listener stopped", "address", addr, "err", err)
			}
		}(srv, ln, l.Address)
	}
	return nil
}

// Addrs returns the actual bound addresses (useful when a listener used :0).
func (s *Server) Addrs() []net.Addr {
	out := make([]net.Addr, len(s.lns))
	for i, ln := range s.lns {
		out[i] = ln.Addr()
	}
	return out
}

// Close stops all listeners.
func (s *Server) Close() {
	for _, srv := range s.servers {
		srv.Close()
	}
}

// NewSession enforces the optional IP allowlist and starts a session.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remote := c.Conn().RemoteAddr()
	if len(b.allowNets) > 0 {
		host, _, _ := net.SplitHostPort(remote.String())
		ip := net.ParseIP(host)
		if ip == nil || !b.ipAllowed(ip) {
			err := &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "connection not permitted"}
			b.recordRejection("connect", remote.String(), "", "", "", err)
			return nil, err
		}
	}
	return &session{be: b, remote: remote.String()}, nil
}

// recordRejection logs a refused request to stderr and persists it for later
// inspection via the `rejections` subcommand.
func (b *Backend) recordRejection(stage, remote, username, from, rcpt string, e *smtp.SMTPError) {
	b.log.Warn("rejected request",
		"stage", stage, "code", e.Code, "reason", e.Message,
		"remote", remote, "user", username, "from", from, "rcpt", rcpt)
	if err := b.store.LogRejection(store.Rejection{
		At: time.Now(), Stage: stage, Code: e.Code,
		RemoteAddr: remote, Username: username, From: from, Rcpt: rcpt, Reason: e.Message,
	}); err != nil {
		b.log.Error("failed to persist rejection", "err", err)
	}
}

func (b *Backend) ipAllowed(ip net.IP) bool {
	for _, n := range b.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// recipient pairs an envelope address with the route it matched.
type recipient struct {
	addr  string
	route config.Route
}

type session struct {
	be       *Backend
	remote   string
	username string
	from     string
	rcpts    []recipient
}

// reject records a rejection with the session's current envelope context and
// returns the error to hand back to go-smtp.
func (s *session) reject(stage, rcpt string, e *smtp.SMTPError) error {
	s.be.recordRejection(stage, s.remote, s.username, s.from, rcpt, e)
	return e
}

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	validate := func(username, password string) error {
		u, ok := s.be.users[username]
		if !ok {
			// Compare against a dummy bcrypt to reduce username enumeration timing.
			bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinva"), []byte(password))
			// Record with the attempted username (s.username is still unset).
			s.be.recordRejection("auth", s.remote, username, "", "", errAuthFailed)
			return errAuthFailed
		}
		if !checkPassword(u, password) {
			s.be.recordRejection("auth", s.remote, username, "", "", errAuthFailed)
			return errAuthFailed
		}
		s.username = username
		return nil
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return validate(username, password)
		}), nil
	case sasl.Login:
		return newLoginServer(validate), nil
	default:
		return nil, smtp.ErrAuthUnsupported
	}
}

var errAuthFailed = &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "authentication failed"}

func checkPassword(c credential, password string) bool {
	if c.passwordBcrypt != "" {
		return bcrypt.CompareHashAndPassword([]byte(c.passwordBcrypt), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(c.password), []byte(password)) == 1
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.username == "" {
		return s.reject("mail", "", &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "authentication required"})
	}
	s.from = from
	return nil
}

// Rcpt matches the recipient to a route owned by the authenticated user,
// rejecting recipients with no such route so senders learn immediately rather
// than having mail silently dropped.
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	route, ok := s.be.router.Match(s.username, to)
	if !ok {
		return s.reject("rcpt", to, &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no route configured for recipient"})
	}
	s.rcpts = append(s.rcpts, recipient{addr: to, route: route})
	return nil
}

func (s *session) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	receivedAt := time.Now()
	id := s.be.newID()
	msg := mail.Parse(s.from, s.rcptAddrs(), raw)

	// Distinct matched routes, preserving first-seen order.
	var order []string
	routes := map[string]config.Route{}
	for _, rc := range s.rcpts {
		if _, seen := routes[rc.route.Name]; !seen {
			routes[rc.route.Name] = rc.route
			order = append(order, rc.route.Name)
		}
	}

	if err := s.be.store.LogMessage(store.MessageLog{
		ID: id, ReceivedAt: receivedAt, From: s.from, Rcpt: s.rcptAddrs(),
		Route: strings.Join(order, ","), Subject: msg.Subject, Size: len(raw),
		RemoteAddr: s.remote, Username: s.username, Raw: raw,
	}); err != nil {
		s.be.log.Error("failed to log message", "message_id", id, "err", err)
	}

	// Deliver sync routes inline first: a failure rejects the whole message so
	// the sender retries. Async routes are enqueued only once sync ones succeed.
	var asyncRoutes []config.Route
	for _, name := range order {
		route := routes[name]
		// Capture-only route (no webhook): the message is already stored above;
		// accept it and move on without delivering anywhere.
		if !route.HasWebhook() {
			s.be.log.Info("captured message (no webhook)", "route", name, "message_id", id)
			continue
		}
		payload := delivery.BuildPayload(id, receivedAt, route, msg)
		if route.EffectiveMode(s.be.cfg.Delivery.DefaultMode) == config.ModeSync {
			ctx, cancel := context.WithTimeout(context.Background(), s.be.cfg.Delivery.Timeout.D())
			code, derr := s.be.deliverer.DeliverSync(ctx, route, payload)
			cancel()
			if derr != nil {
				return s.reject("data", strings.Join(s.rcptAddrs(), ","),
					&smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0},
						Message: fmt.Sprintf("downstream webhook for route %q rejected message (status %d), try again later", name, code)})
			}
			s.be.log.Info("sync delivered", "route", name, "message_id", id, "status", code)
		} else {
			asyncRoutes = append(asyncRoutes, route)
		}
	}
	for _, route := range asyncRoutes {
		payload := delivery.BuildPayload(id, receivedAt, route, msg)
		if err := s.be.deliverer.Enqueue(payload); err != nil {
			s.be.log.Error("failed to enqueue async delivery", "route", route.Name, "message_id", id, "err", err)
			return s.reject("data", strings.Join(s.rcptAddrs(), ","),
				&smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "temporary failure queuing message"})
		}
		s.be.log.Info("queued async delivery", "route", route.Name, "message_id", id)
	}
	return nil
}

func (s *session) rcptAddrs() []string {
	out := make([]string, len(s.rcpts))
	for i, rc := range s.rcpts {
		out[i] = rc.addr
	}
	return out
}

func (s *session) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *session) Logout() error { return nil }
