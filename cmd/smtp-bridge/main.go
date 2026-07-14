// Command smtp-bridge runs an SMTP server that converts accepted mail into
// webhook HTTP requests. See config.example.yaml for configuration.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/cinderblock/smtp-bridge/internal/config"
	"github.com/cinderblock/smtp-bridge/internal/delivery"
	"github.com/cinderblock/smtp-bridge/internal/router"
	"github.com/cinderblock/smtp-bridge/internal/server"
	"github.com/cinderblock/smtp-bridge/internal/store"
)

func main() {
	// Subcommands come before flags: `smtp-bridge rejections [-config ...] [-n N]`.
	if len(os.Args) > 1 && os.Args[1] == "rejections" {
		runRejections(os.Args[2:])
		return
	}
	runServer()
}

func runServer() {
	configPath := flag.String("config", "config.yaml", "path to the YAML config file")
	debug := flag.Bool("debug", false, "enable debug logging")
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

	srv, err := server.New(cfg, rt, d, st, log, func() string { return uuid.NewString() })
	if err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}

	go func() {
		log.Info("smtp-bridge listening",
			"addr", cfg.Listen, "hostname", cfg.Hostname,
			"tls", cfg.TLS.Enabled(), "logging", cfg.Logging.Enabled,
			"routes", len(cfg.Routes))
		if err := srv.ListenAndServe(); err != nil {
			log.Error("listener stopped", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	srv.Close()
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
		fmt.Printf("%s  stage=%-5s code=%d  ip=%s user=%q from=%q rcpt=%q  reason=%q\n",
			r.At.Format(time.RFC3339), r.Stage, r.Code, r.RemoteAddr, r.Username, r.From, r.Rcpt, r.Reason)
	}
}
