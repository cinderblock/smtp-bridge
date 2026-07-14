// Package delivery turns a parsed message into a signed webhook POST and
// handles both synchronous and durable-async delivery.
package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/cinderblock/smtp-bridge/internal/config"
	"github.com/cinderblock/smtp-bridge/internal/mail"
	"github.com/cinderblock/smtp-bridge/internal/store"
)

// Payload is the JSON body POSTed to a route's webhook.
type Payload struct {
	MessageID   string            `json:"message_id"`
	ReceivedAt  time.Time         `json:"received_at"`
	Route       string            `json:"route"`
	From        string            `json:"from"`
	Rcpt        []string          `json:"rcpt"`
	Subject     string            `json:"subject"`
	Headers     map[string]string `json:"headers"`
	Text        string            `json:"text,omitempty"`
	HTML        string            `json:"html,omitempty"`
	Attachments []Attachment      `json:"attachments,omitempty"`
	RawEML      string            `json:"raw_eml_b64,omitempty"`
}

// Attachment is one attachment in the payload. ContentB64 is omitted when the
// route does not include attachment bodies or a size cap is exceeded.
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
	ContentB64  string `json:"content_b64,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// BuildPayload constructs the webhook payload for a message under a route's rules.
func BuildPayload(messageID string, receivedAt time.Time, route config.Route, m *mail.Message) *Payload {
	p := &Payload{
		MessageID:  messageID,
		ReceivedAt: receivedAt,
		Route:      route.Name,
		From:       m.From,
		Rcpt:       m.Rcpt,
		Subject:    m.Subject,
		Headers:    m.Headers,
		Text:       m.Text,
		HTML:       m.HTML,
	}
	for _, a := range m.Attachments {
		att := Attachment{
			Filename:    a.Filename,
			ContentType: a.ContentType,
			Size:        len(a.Content),
		}
		if route.Include.Attachments {
			if route.Include.MaxAttachmentBytes > 0 && int64(len(a.Content)) > route.Include.MaxAttachmentBytes {
				att.Truncated = true
			} else {
				att.ContentB64 = base64.StdEncoding.EncodeToString(a.Content)
			}
		}
		p.Attachments = append(p.Attachments, att)
	}
	if route.Include.Raw {
		p.RawEML = base64.StdEncoding.EncodeToString(m.Raw)
	}
	return p
}

// Deliverer performs webhook deliveries and runs the async queue worker.
type Deliverer struct {
	cfg    *config.Delivery
	routes map[string]config.Route
	store  *store.Store
	client *http.Client
	log    *slog.Logger
}

// New creates a Deliverer. routes maps route name -> Route.
func New(cfg *config.Delivery, routes map[string]config.Route, st *store.Store, log *slog.Logger) *Deliverer {
	return &Deliverer{
		cfg:    cfg,
		routes: routes,
		store:  st,
		client: &http.Client{Timeout: cfg.Timeout.D()},
		log:    log,
	}
}

// attempt performs a single HTTP POST. It returns the status code and, on a
// non-2xx or transport error, a non-nil error.
func (d *Deliverer) attempt(ctx context.Context, route config.Route, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, route.Webhook.Method, route.Webhook.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "smtp-bridge")
	req.Header.Set("X-SMTP-Bridge-Route", route.Name)
	if route.Webhook.Secret != "" {
		mac := hmac.New(sha256.New, []byte(route.Webhook.Secret))
		mac.Write(body)
		req.Header.Set("X-SMTP-Bridge-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	for k, v := range route.Webhook.Headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// DeliverSync POSTs immediately and reports success (2xx). Used for sync routes;
// the caller maps failure to an SMTP rejection.
func (d *Deliverer) DeliverSync(ctx context.Context, route config.Route, p *Payload) (int, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return 0, err
	}
	code, err := d.attempt(ctx, route, body)
	d.store.LogDelivery(p.MessageID, route.Name, 1, code, err == nil, errStr(err))
	return code, err
}

// Enqueue serializes the payload and stores it for async delivery.
func (d *Deliverer) Enqueue(p *Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return d.store.Enqueue(p.MessageID, p.Route, body)
}

// RunWorker polls the queue and delivers due jobs until ctx is cancelled.
func (d *Deliverer) RunWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.drain(ctx)
		}
	}
}

func (d *Deliverer) drain(ctx context.Context) {
	jobs, err := d.store.ClaimDue(d.cfg.Concurrency * 4)
	if err != nil {
		d.log.Error("queue claim failed", "err", err)
		return
	}
	// Bounded concurrency across the claimed batch.
	sem := make(chan struct{}, d.cfg.Concurrency)
	for _, j := range jobs {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		go func(j store.Job) {
			defer func() { <-sem }()
			d.process(ctx, j)
		}(j)
	}
	// Wait for in-flight jobs to settle before the next tick.
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}
}

func (d *Deliverer) process(ctx context.Context, j store.Job) {
	route, ok := d.routes[j.Route]
	if !ok {
		d.log.Warn("dropping job for unknown route", "route", j.Route, "message_id", j.MessageID)
		d.store.CompleteJob(j.ID)
		return
	}
	attempt := j.Attempts + 1
	code, err := d.attempt(ctx, route, j.Payload)
	d.store.LogDelivery(j.MessageID, j.Route, attempt, code, err == nil, errStr(err))
	if err == nil {
		d.store.CompleteJob(j.ID)
		d.log.Info("delivered", "route", j.Route, "message_id", j.MessageID, "attempt", attempt, "status", code)
		return
	}
	if attempt >= d.cfg.MaxRetries {
		d.log.Error("giving up on delivery", "route", j.Route, "message_id", j.MessageID, "attempts", attempt, "err", err)
		d.store.CompleteJob(j.ID)
		return
	}
	// Exponential backoff: base * 2^(attempt-1).
	backoff := d.cfg.RetryBackoff.D() * time.Duration(1<<(attempt-1))
	next := time.Now().Add(backoff)
	if err := d.store.RescheduleJob(j.ID, attempt, next); err != nil {
		d.log.Error("reschedule failed", "message_id", j.MessageID, "err", err)
	}
	d.log.Warn("delivery failed, will retry", "route", j.Route, "message_id", j.MessageID, "attempt", attempt, "next", next, "err", err)
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
