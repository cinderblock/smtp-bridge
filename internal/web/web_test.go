package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cinderblock/smtp-bridge/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"), true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	raw := "Subject: Captured Subject\r\nFrom: sender@x.com\r\n\r\nthe body text\r\n"
	if err := st.LogMessage(store.MessageLog{
		ID: "m1", ReceivedAt: time.Now(), From: "sender@x.com",
		Rcpt: []string{"t-mobile@kitchen1.sos"}, Route: "t-mobile-kitchen1",
		Subject: "Captured Subject", Size: len(raw), Username: "kitchen1", Port: 465, Raw: []byte(raw),
	}); err != nil {
		t.Fatal(err)
	}
	st.LogRejection(store.Rejection{At: time.Now(), Stage: "auth", Code: 535, Username: "baduser", Reason: "authentication failed", Port: 587})
	return New(st), st
}

func get(t *testing.T, h http.Handler, path string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	return rr, rr.Body.String()
}

func TestList(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	rr, body := get(t, h, "/")
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	for _, want := range []string{"Captured Subject", "kitchen1", "t-mobile@kitchen1.sos", "/message/m1", ">465<"} {
		if !strings.Contains(body, want) {
			t.Errorf("list missing %q", want)
		}
	}
}

func TestDetailAndRaw(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	rr, body := get(t, h, "/message/m1")
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	for _, want := range []string{"Captured Subject", "the body text", "raw .eml"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	rr, raw := get(t, h, "/message/m1/raw")
	if rr.Code != 200 || !strings.Contains(raw, "the body text") {
		t.Errorf("raw = %d %q", rr.Code, raw)
	}
	rr, _ = get(t, h, "/message/nope")
	if rr.Code != 404 {
		t.Errorf("missing message should 404, got %d", rr.Code)
	}
}

func TestRejectionsView(t *testing.T) {
	s, _ := newTestServer(t)
	rr, body := get(t, s.Handler(), "/rejections")
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(body, "authentication failed") || !strings.Contains(body, "baduser") {
		t.Error("rejections view missing expected rows")
	}
	if !strings.Contains(body, ">587<") {
		t.Error("rejections view missing the arrival port")
	}
}

func post(t *testing.T, h http.Handler, path, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestDeleteSelected(t *testing.T) {
	s, st := newTestServer(t)
	h := s.Handler()
	rr := post(t, h, "/delete", "id=m1")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	msgs, _ := st.RecentMessages(10)
	if len(msgs) != 0 {
		t.Errorf("m1 should be gone, %d left", len(msgs))
	}
}

func TestDeleteAll(t *testing.T) {
	s, st := newTestServer(t)
	// add a second message so "all" clearly clears more than one
	st.LogMessage(store.MessageLog{ID: "m2", ReceivedAt: time.Now(), From: "b@c", Rcpt: []string{"x@y"}, Size: 1, Raw: []byte("Subject: two\r\n\r\nx")})
	rr := post(t, s.Handler(), "/delete", "all=1")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	if msgs, _ := st.RecentMessages(10); len(msgs) != 0 {
		t.Errorf("all messages should be gone, %d left", len(msgs))
	}
}

// HTML bodies must be shown as escaped source, never rendered as live markup.
func TestHTMLBodyIsEscaped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "x.db"), true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	raw := "Subject: x\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>\r\n"
	st.LogMessage(store.MessageLog{ID: "h1", ReceivedAt: time.Now(), From: "a@b", Rcpt: []string{"x@y"}, Size: len(raw), Raw: []byte(raw)})
	_, body := get(t, New(st).Handler(), "/message/h1")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("raw <script> must be escaped in the HTML view, not emitted live")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("expected escaped script tag in output")
	}
}
