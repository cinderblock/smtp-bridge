// Command smtp-bridge runs an SMTP server that converts accepted mail into
// webhook HTTP requests. See config.example.yaml for configuration.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/cinderblock/smtp-bridge/internal/config"
	"github.com/cinderblock/smtp-bridge/internal/delivery"
	"github.com/cinderblock/smtp-bridge/internal/router"
	"github.com/cinderblock/smtp-bridge/internal/server"
	"github.com/cinderblock/smtp-bridge/internal/store"
	"github.com/cinderblock/smtp-bridge/internal/tlsconf"
	"github.com/cinderblock/smtp-bridge/internal/web"
)

func main() {
	// Subcommands come before flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "rejections":
			runRejections(os.Args[2:])
			return
		case "messages":
			runMessages(os.Args[2:])
			return
		case "hash":
			runHash(os.Args[2:])
			return
		}
	}
	runServer()
}

// runHash prints a bcrypt hash of a password, for use as a route's
// password_bcrypt. Reads the password from the first arg or from stdin.
func runHash(argv []string) {
	var pw string
	if len(argv) > 0 && argv[0] != "" {
		pw = argv[0]
	} else {
		b, _ := io.ReadAll(os.Stdin)
		pw = strings.TrimRight(string(b), "\r\n")
	}
	if pw == "" {
		fmt.Fprintln(os.Stderr, "usage: smtp-bridge hash <password>   (or pipe the password on stdin)")
		os.Exit(1)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash error:", err)
		os.Exit(1)
	}
	fmt.Println(string(h))
}

func runServer() {
	configPath := flag.String("config", "config.yaml", "path to the YAML config file")
	debug := flag.Bool("debug", false, "enable debug logging")
	check := flag.Bool("check", false, "validate the config and exit (no listeners, no ACME)")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("config error", "err", err)
		os.Exit(1)
	}
	if *check {
		fmt.Printf("config OK: %d listener(s), %d route(s), cert mode %q\n",
			len(cfg.Listeners), len(cfg.Routes), cfg.TLS.Mode)
		return
	}

	st, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled, cfg.Logging.LogRejections())
	if err != nil {
		log.Error("store error", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	routeMap := make(map[string]config.Route, len(cfg.Routes))
	for _, r := range cfg.Routes {
		routeMap[r.Name] = r
	}

	rt := router.New(cfg.Routes)
	d := delivery.New(&cfg.Delivery, routeMap, st, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Async delivery worker.
	go d.RunWorker(ctx)

	// Auto-purge old rejections if a retention period is configured.
	if days := cfg.Logging.RejectionRetentionDays; days > 0 {
		go runRejectionPurge(ctx, st, log, days)
	}

	// Build the shared TLS certificate source (may obtain a cert via ACME).
	tlsConfig, err := tlsconf.Build(ctx, cfg.TLS, log)
	if err != nil {
		log.Error("tls setup error", "err", err)
		os.Exit(1)
	}

	srv, err := server.New(cfg, rt, d, st, log, func() string { return uuid.NewString() }, tlsConfig)
	if err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}

	// Optional read-only status web UI (no auth — keep it loopback-only).
	var webSrv *http.Server
	if cfg.Web.Enabled() {
		webSrv = &http.Server{Addr: cfg.Web.Listen, Handler: web.New(st).Handler()}
		go func() {
			log.Info("web UI listening (NO AUTH — keep it off public interfaces)", "addr", cfg.Web.Listen)
			if err := webSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("web UI stopped", "err", err)
			}
		}()
	}

	log.Info("smtp-bridge starting",
		"hostname", cfg.Hostname, "listeners", len(cfg.Listeners),
		"cert_mode", string(cfg.TLS.Mode), "logging", cfg.Logging.Enabled,
		"web", cfg.Web.Listen, "routes", len(cfg.Routes))
	if err := srv.Serve(); err != nil {
		log.Error("failed to start listeners", "err", err)
		os.Exit(1)
	}

	<-ctx.Done()
	log.Info("shutting down")
	srv.Close()
	if webSrv != nil {
		webSrv.Close()
	}
}

// runRejectionPurge deletes rejections older than `days` days at startup and
// then every 6h, until ctx is cancelled.
func runRejectionPurge(ctx context.Context, st *store.Store, log *slog.Logger, days int) {
	purge := func() {
		cutoff := time.Now().AddDate(0, 0, -days)
		if n, err := st.PurgeRejectionsOlderThan(cutoff); err != nil {
			log.Error("rejection purge failed", "err", err)
		} else if n > 0 {
			log.Info("purged old rejections", "count", n, "retention_days", days)
		}
	}
	purge()
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
}

// runRejections prints recently rejected requests from the database, newest
// first — a quick way to see who was refused and why.
func runRejections(argv []string) {
	fs := flag.NewFlagSet("rejections", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to the YAML config file")
	n := fs.Int("n", 50, "number of recent rejections to show")
	fs.Parse(argv)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	st, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled, cfg.Logging.LogRejections())
	if err != nil {
		fmt.Fprintln(os.Stderr, "store error:", err)
		os.Exit(1)
	}
	defer st.Close()

	rows, err := st.RecentRejections(*n)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query error:", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Println("no rejections recorded")
		return
	}
	// Newest first from the query; print oldest-first so a tail reads naturally.
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		fmt.Printf("%s  port=%d stage=%-5s code=%d  ip=%s user=%q from=%q rcpt=%q  reason=%q\n",
			r.At.Format(time.RFC3339), r.Port, r.Stage, r.Code, r.RemoteAddr, r.Username, r.From, r.Rcpt, r.Reason)
	}
}

// runMessages prints recently logged messages (including capture-only routes),
// newest first — a quick way to see what mail has arrived.
func runMessages(argv []string) {
	fs := flag.NewFlagSet("messages", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to the YAML config file")
	n := fs.Int("n", 50, "number of recent messages to show")
	fs.Parse(argv)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	st, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled, cfg.Logging.LogRejections())
	if err != nil {
		fmt.Fprintln(os.Stderr, "store error:", err)
		os.Exit(1)
	}
	defer st.Close()

	rows, err := st.RecentMessages(*n)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query error:", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Println("no messages logged (is logging.enabled true?)")
		return
	}
	for i := len(rows) - 1; i >= 0; i-- {
		m := rows[i]
		fmt.Printf("%s  port=%d user=%q route=%q from=%q rcpt=%q size=%d  subject=%q\n",
			m.ReceivedAt.Format(time.RFC3339), m.Port, m.Username, m.Route, m.From, m.Rcpt, m.Size, m.Subject)
	}
}
