// Command smtp-bridge runs an SMTP server that converts accepted mail into
// webhook HTTP requests. See config.example.yaml for configuration.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"

	"github.com/cinderblock/smtp-bridge/internal/config"
	"github.com/cinderblock/smtp-bridge/internal/delivery"
	"github.com/cinderblock/smtp-bridge/internal/router"
	"github.com/cinderblock/smtp-bridge/internal/server"
	"github.com/cinderblock/smtp-bridge/internal/store"
)

func main() {
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

	st, err := store.Open(cfg.Logging.Database, cfg.Logging.Enabled)
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
