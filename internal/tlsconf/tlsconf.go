// Package tlsconf builds the server *tls.Config shared by all TLS-enabled
// listeners, from one of three certificate sources: none, static files, or
// automatic ACME DNS-01 issuance (Cloudflare) via certmagic.
package tlsconf

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"

	"github.com/cinderblock/smtp-bridge/internal/config"
)

// Build returns the server TLS config for the given certificate source, or nil
// when no certificate is needed (CertModeNone). For CertModeAuto it obtains the
// certificate synchronously (DNS-01) so a bad token/DNS fails fast at startup;
// renewals then happen in the background.
func Build(ctx context.Context, c config.TLS, log *slog.Logger) (*tls.Config, error) {
	switch c.Mode {
	case config.CertModeNone:
		return nil, nil

	case config.CertModeFiles:
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS keypair: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil

	case config.CertModeAuto:
		return buildAuto(ctx, c, log)

	default:
		return nil, fmt.Errorf("unknown tls.mode %q", c.Mode)
	}
}

func buildAuto(ctx context.Context, c config.TLS, log *slog.Logger) (*tls.Config, error) {
	token := c.CFAPIToken
	if token == "" {
		token = os.Getenv("CLOUDFLARE_API_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("cloudflare API token missing (tls.cf_api_token or $CLOUDFLARE_API_TOKEN)")
	}

	solver := &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflare.Provider{APIToken: token},
		},
	}

	storage := &certmagic.FileStorage{Path: c.StoragePath}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})
	magic = certmagic.New(cache, certmagic.Config{
		Storage: storage,
		Logger:  zap.NewNop(),
	})

	acme := certmagic.ACMEIssuer{
		Email:       c.ACMEEmail,
		Agreed:      true,
		DNS01Solver: solver,
	}
	if c.CADirURL != "" {
		acme.CA = c.CADirURL // e.g. Let's Encrypt staging for testing
	}
	magic.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(magic, acme)}

	log.Info("obtaining/loading TLS certificate via ACME DNS-01",
		"hostnames", c.Hostnames, "storage", c.StoragePath)
	if err := magic.ManageSync(ctx, c.Hostnames); err != nil {
		return nil, fmt.Errorf("manage certificate for %v: %w", c.Hostnames, err)
	}
	log.Info("TLS certificate ready", "hostnames", c.Hostnames)

	tlsCfg := magic.TLSConfig()
	// We solve DNS-01, never TLS-ALPN, and these are SMTP ports — don't advertise
	// the ACME/HTTP ALPN protocols certmagic adds by default.
	tlsCfg.NextProtos = nil
	return tlsCfg, nil
}
