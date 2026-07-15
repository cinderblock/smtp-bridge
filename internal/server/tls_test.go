package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cinderblock/smtp-bridge/internal/config"
	"github.com/cinderblock/smtp-bridge/internal/delivery"
	"github.com/cinderblock/smtp-bridge/internal/router"
	"github.com/cinderblock/smtp-bridge/internal/server"
	"github.com/cinderblock/smtp-bridge/internal/store"
	"github.com/cinderblock/smtp-bridge/internal/tlsconf"
)

// genCert writes a self-signed cert+key valid for localhost/127.0.0.1 and
// returns the file paths plus a cert pool that trusts it.
func genCert(t *testing.T) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return certPath, keyPath, pool
}

// startTLSBridge starts a bridge with the given listeners + files-mode cert and
// returns the bound address of each listener (same order as cfg.Listeners).
func startTLSBridge(t *testing.T, listeners []config.Listener, certPath, keyPath, webhookURL string) (addrs []string, cleanup func()) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Listeners: listeners,
		Hostname:  "localhost",
		Auth:      config.Auth{Users: []config.User{{Username: "alice", Password: "s3cret"}}},
		Logging:   config.Logging{Enabled: true, Database: filepath.Join(t.TempDir(), "test.db")},
		Delivery:  config.Delivery{DefaultMode: config.ModeSync},
		TLS:       config.TLS{Mode: config.CertModeFiles, CertFile: certPath, KeyFile: keyPath},
		Routes: []config.Route{{
			Name:    "app",
			Match:   config.Match{RcptDomain: "hooks.example.com"},
			Webhook: config.Webhook{URL: webhookURL},
		}},
	}
	if err := cfg.Prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	st, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled, cfg.Logging.LogRejections())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	routeMap := map[string]config.Route{"app": cfg.Routes[0]}
	rt := router.New(cfg.Routes)
	d := delivery.New(&cfg.Delivery, routeMap, st, log)
	ctx, cancel := context.WithCancel(context.Background())
	go d.RunWorker(ctx)
	tlsConfig, err := tlsconf.Build(ctx, cfg.TLS, log)
	if err != nil {
		t.Fatalf("tls build: %v", err)
	}
	var n int
	srv, err := server.New(cfg, rt, d, st, log, func() string { n++; return "tls-" + strconv.Itoa(n) }, tlsConfig)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := srv.Serve(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	for _, a := range srv.Addrs() {
		addrs = append(addrs, a.String())
	}
	return addrs, func() { cancel(); srv.Close(); st.Close() }
}

func TestImplicitTLSListener(t *testing.T) {
	got := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- struct{}{}:
		default:
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	certPath, keyPath, pool := genCert(t)
	addrs, cleanup := startTLSBridge(t,
		[]config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSModeImplicit}},
		certPath, keyPath, ts.URL)
	defer cleanup()

	// Implicit TLS: the whole connection is TLS from the first byte.
	conn, err := tls.Dial("tcp", addrs[0], &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	c, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()
	if err := c.Auth(smtp.PlainAuth("", "alice", "s3cret", "localhost")); err != nil {
		t.Fatalf("auth over implicit TLS: %v", err)
	}
	if err := sendBody(c, "s@x.com", "a@hooks.example.com"); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called")
	}
}

func TestStartTLSListenerRequiresTLSForAuth(t *testing.T) {
	got := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- struct{}{}:
		default:
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	certPath, keyPath, pool := genCert(t)
	addrs, cleanup := startTLSBridge(t,
		[]config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSModeStartTLS}},
		certPath, keyPath, ts.URL)
	defer cleanup()

	// serverName "localhost" so it matches both the cert and PlainAuth's host check.
	newClient := func() *smtp.Client {
		conn, err := net.Dial("tcp", addrs[0])
		if err != nil {
			t.Fatal(err)
		}
		c, err := smtp.NewClient(conn, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// AUTH before STARTTLS must be refused (AllowInsecureAuth defaults false).
	c1 := newClient()
	if err := c1.Auth(smtp.PlainAuth("", "alice", "s3cret", "localhost")); err == nil {
		t.Error("expected AUTH before STARTTLS to be refused")
	}
	c1.Close()

	// After STARTTLS, AUTH + send works.
	c2 := newClient()
	defer c2.Close()
	if err := c2.StartTLS(&tls.Config{RootCAs: pool, ServerName: "localhost"}); err != nil {
		t.Fatalf("starttls: %v", err)
	}
	if err := c2.Auth(smtp.PlainAuth("", "alice", "s3cret", "localhost")); err != nil {
		t.Fatalf("auth after starttls: %v", err)
	}
	if err := sendBody(c2, "s@x.com", "a@hooks.example.com"); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called")
	}
}

func sendBody(c *smtp.Client, from, to string) error {
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
	if _, err := w.Write([]byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		return err
	}
	return w.Close()
}
