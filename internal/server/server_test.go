package server_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cinderblock/smtp-bridge/internal/config"
	"github.com/cinderblock/smtp-bridge/internal/delivery"
	"github.com/cinderblock/smtp-bridge/internal/router"
	"github.com/cinderblock/smtp-bridge/internal/server"
	"github.com/cinderblock/smtp-bridge/internal/store"
	"github.com/cinderblock/smtp-bridge/internal/tlsconf"
)

type capture struct {
	mu   sync.Mutex
	body []byte
	sig  string
	got  bool
}

func startBridge(t *testing.T, cfg *config.Config) (addr string, cleanup func()) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled, cfg.Logging.LogRejections())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	routeMap := map[string]config.Route{}
	for _, r := range cfg.Routes {
		routeMap[r.Name] = r
	}
	rt := router.New(cfg.Routes)
	d := delivery.New(&cfg.Delivery, routeMap, st, log)
	ctx, cancel := context.WithCancel(context.Background())
	go d.RunWorker(ctx)

	tlsConfig, err := tlsconf.Build(ctx, cfg.TLS, log)
	if err != nil {
		cancel()
		t.Fatalf("tls build: %v", err)
	}

	var n int
	srv, err := server.New(cfg, rt, d, st, log, func() string { n++; return "id-" + strconv.Itoa(n) }, tlsConfig)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := srv.Serve(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	return srv.Addrs()[0].String(), func() {
		cancel()
		srv.Close()
		st.Close()
	}
}

func send(t *testing.T, addr string, from string, to string, body string) error {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	// serverName "localhost" so net/smtp permits PLAIN over the loopback connection.
	c, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Auth(smtp.PlainAuth("", "alice", "s3cret", "localhost")); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(body)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func baseConfig(t *testing.T, mode config.Mode, webhookURL, secret string) *config.Config {
	cfg := &config.Config{
		Listeners: []config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSModeNone}},
		Hostname:  "localhost",
		Logging:   config.Logging{Enabled: true, Database: filepath.Join(t.TempDir(), "test.db")},
		Delivery:  config.Delivery{DefaultMode: mode, MaxRetries: 3},
		Routes: []config.Route{{
			Name:     "app",
			Username: "alice",
			Password: "s3cret",
			Match:    config.Match{RcptDomain: "hooks.example.com"},
			Webhook:  config.Webhook{URL: webhookURL, Secret: secret},
			Include:  config.IncludeRules{Raw: true},
		}},
	}
	// Apply the same defaults/validation the loader does.
	if err := cfg.Prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return cfg
}

func TestSyncDelivery(t *testing.T) {
	cap := &capture{}
	secret := "hmac-key"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.mu.Lock()
		cap.body = b
		cap.sig = r.Header.Get("X-SMTP-Bridge-Signature")
		cap.got = true
		cap.mu.Unlock()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	cfg := baseConfig(t, config.ModeSync, ts.URL, secret)
	addr, cleanup := startBridge(t, cfg)
	defer cleanup()

	body := "Subject: Hello\r\nFrom: sender@x.com\r\n\r\nThis is the body.\r\n"
	if err := send(t, addr, "sender@x.com", "myapp@hooks.example.com", body); err != nil {
		t.Fatalf("send: %v", err)
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if !cap.got {
		t.Fatal("webhook not called")
	}
	var p delivery.Payload
	if err := json.Unmarshal(cap.body, &p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.Subject != "Hello" {
		t.Errorf("subject = %q, want Hello", p.Subject)
	}
	if p.From != "sender@x.com" {
		t.Errorf("from = %q", p.From)
	}
	if len(p.Rcpt) != 1 || p.Rcpt[0] != "myapp@hooks.example.com" {
		t.Errorf("rcpt = %v", p.Rcpt)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(cap.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if cap.sig != want {
		t.Errorf("signature = %q, want %q", cap.sig, want)
	}
}

func TestAsyncDeliveryRetries(t *testing.T) {
	var calls int
	var mu sync.Mutex
	done := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n < 2 { // fail first attempt, succeed on retry
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		select {
		case <-done:
		default:
			close(done)
		}
	}))
	defer ts.Close()

	cfg := baseConfig(t, config.ModeAsync, ts.URL, "")
	cfg.Delivery.RetryBackoff = config.Duration(200 * time.Millisecond)
	addr, cleanup := startBridge(t, cfg)
	defer cleanup()

	body := "Subject: Q\r\n\r\nbody\r\n"
	if err := send(t, addr, "s@x.com", "a@hooks.example.com", body); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("async delivery did not succeed within timeout")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls < 2 {
		t.Errorf("expected retry, got %d calls", calls)
	}
}

func TestRejectsUnroutedRecipient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()
	cfg := baseConfig(t, config.ModeAsync, ts.URL, "")
	addr, cleanup := startBridge(t, cfg)
	defer cleanup()

	err := send(t, addr, "s@x.com", "nobody@elsewhere.net", "Subject: x\r\n\r\nx\r\n")
	if err == nil {
		t.Fatal("expected rejection for unrouted recipient")
	}
}

func TestCaptureOnlyRoute(t *testing.T) {
	// A route with no webhook: mail should be accepted (250) and stored, and no
	// HTTP delivery attempted.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cfg := &config.Config{
		Listeners: []config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSModeNone}},
		Hostname:  "localhost",
		Logging:   config.Logging{Enabled: true, Database: dbPath},
		Delivery:  config.Delivery{DefaultMode: config.ModeAsync},
		Routes: []config.Route{{
			Name:     "capture",
			Username: "kitchen1",
			Password: "pw",
			Match:    config.Match{Rcpt: "t-mobile@kitchen1.sos"},
			// no webhook -> capture-only
		}},
	}
	if err := cfg.Prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	st, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled, cfg.Logging.LogRejections())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	rt := router.New(cfg.Routes)
	d := delivery.New(&cfg.Delivery, map[string]config.Route{"capture": cfg.Routes[0]}, st, log)
	ctx, cancel := context.WithCancel(context.Background())
	go d.RunWorker(ctx)
	var n int
	srv, err := server.New(cfg, rt, d, st, log, func() string { n++; return "cap-" + strconv.Itoa(n) }, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := srv.Serve(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { cancel(); srv.Close(); st.Close() }()
	addr := srv.Addrs()[0].String()

	// Authenticate as the route's user and send to the captured address.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Auth(smtp.PlainAuth("", "kitchen1", "pw", "localhost")); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := c.Mail("verizon@somewhere"); err != nil {
		t.Fatalf("mail: %v", err)
	}
	if err := c.Rcpt("t-mobile@kitchen1.sos"); err != nil {
		t.Fatalf("rcpt (should be accepted): %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("Subject: hello from tmobile\r\n\r\nbody\r\n"))
	if err := w.Close(); err != nil {
		t.Fatalf("data close (should be accepted): %v", err)
	}
	c.Quit()

	// The message must be stored (captured), with the right route/user.
	msgs, err := st.RecentMessages(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 captured message, got %d", len(msgs))
	}
	if msgs[0].Route != "capture" || msgs[0].Username != "kitchen1" {
		t.Errorf("captured message = %+v", msgs[0])
	}
	if msgs[0].Subject != "hello from tmobile" {
		t.Errorf("subject = %q", msgs[0].Subject)
	}
}

func TestRejectionsRecorded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()
	cfg := baseConfig(t, config.ModeAsync, ts.URL, "")
	addr, cleanup := startBridge(t, cfg)
	defer cleanup()

	// Bad auth, then good auth but an unrouted recipient.
	conn, _ := net.Dial("tcp", addr)
	c, _ := smtp.NewClient(conn, "localhost")
	c.Auth(smtp.PlainAuth("", "alice", "wrong", "localhost"))
	c.Close()
	_ = send(t, addr, "s@x.com", "nobody@elsewhere.net", "Subject: x\r\n\r\nx\r\n")

	// Read rejections back from the same database.
	reader, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled, cfg.Logging.LogRejections())
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reader.Close()
	rows, err := reader.RecentRejections(10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	stages := map[string]store.Rejection{}
	for _, r := range rows {
		stages[r.Stage] = r
	}
	if _, ok := stages["auth"]; !ok {
		t.Errorf("expected an auth rejection, got stages %v", keys(stages))
	}
	rc, ok := stages["rcpt"]
	if !ok {
		t.Fatalf("expected an rcpt rejection, got stages %v", keys(stages))
	}
	if rc.Rcpt != "nobody@elsewhere.net" {
		t.Errorf("rcpt rejection rcpt = %q, want nobody@elsewhere.net", rc.Rcpt)
	}
	if rc.Code != 550 {
		t.Errorf("rcpt rejection code = %d, want 550", rc.Code)
	}
}

func keys(m map[string]store.Rejection) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBadAuthRejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()
	cfg := baseConfig(t, config.ModeAsync, ts.URL, "")
	addr, cleanup := startBridge(t, cfg)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Auth(smtp.PlainAuth("", "alice", "wrong", "localhost")); err == nil {
		t.Fatal("expected auth failure")
	}
}
