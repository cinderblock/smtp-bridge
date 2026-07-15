// Package web serves a small read-only, unauthenticated HTML view of stored
// messages and rejections — intended for localhost / SSH-tunnel visibility so you
// don't need the CLI. It never mutates state and never renders untrusted HTML as
// live markup (bodies are shown as escaped source).
package web

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cinderblock/smtp-bridge/internal/mail"
	"github.com/cinderblock/smtp-bridge/internal/store"
)

// Server renders the read-only views over a store.
type Server struct {
	store *store.Store
	tmpl  *template.Template
}

// New builds the web server over the given store.
func New(st *store.Store) *Server {
	return &Server{
		store: st,
		tmpl:  template.Must(template.New("").Funcs(funcs).Parse(templates)),
	}
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleList)
	mux.HandleFunc("GET /message/{id}", s.handleMessage)
	mux.HandleFunc("GET /message/{id}/raw", s.handleRaw)
	mux.HandleFunc("GET /rejections", s.handleRejections)
	return mux
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "n", 200)
	msgs, err := s.store.RecentMessages(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "list", map[string]any{"Nav": "messages", "Messages": msgs})
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, err := s.store.GetMessage(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if m == nil {
		http.NotFound(w, r)
		return
	}
	parsed := mail.Parse(m.From, splitRcpt(m.Rcpt), m.Raw)
	s.render(w, "detail", map[string]any{"Nav": "messages", "M": m, "P": parsed})
}

func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.GetMessage(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if m == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(m.Raw)
}

func (s *Server) handleRejections(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "n", 200)
	rows, err := s.store.RecentRejections(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "rejections", map[string]any{"Nav": "rejections", "Rejections": rows})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func splitRcpt(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

var funcs = template.FuncMap{
	"ts": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
}

const templates = `
{{define "top"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>smtp-bridge</title><style>
:root{color-scheme:light dark}
body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:0 1rem 3rem}
header{display:flex;gap:1rem;align-items:baseline;padding:.75rem 0;border-bottom:1px solid #8884;position:sticky;top:0;background:Canvas}
header h1{font-size:1rem;margin:0}
nav a{margin-right:1rem;text-decoration:none}
nav a.on{font-weight:600;text-decoration:underline}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #8883;vertical-align:top}
th{font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;opacity:.7}
tr:hover td{background:#8881}
code,pre{font-family:ui-monospace,monospace}
pre{white-space:pre-wrap;word-break:break-word;background:#8881;padding:.75rem;border-radius:6px;max-height:32rem;overflow:auto}
.muted{opacity:.6}.mono{font-family:ui-monospace,monospace;font-size:.85rem}
.empty{opacity:.6;margin-top:2rem}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:.2rem .9rem;margin:1rem 0}
.kv dt{opacity:.7}.kv dd{margin:0;word-break:break-word}
</style></head><body>
<header><h1>smtp-bridge</h1><nav>
<a href="/" {{if eq .Nav "messages"}}class="on"{{end}}>Messages</a>
<a href="/rejections" {{if eq .Nav "rejections"}}class="on"{{end}}>Rejections</a>
</nav></header>{{end}}

{{define "bottom"}}</body></html>{{end}}

{{define "list"}}{{template "top" .}}
{{if .Messages}}<table><thead><tr>
<th>Received</th><th>User</th><th>Route</th><th>From</th><th>To</th><th>Subject</th><th>Size</th></tr></thead><tbody>
{{range .Messages}}<tr>
<td class="mono"><a href="/message/{{.ID}}">{{ts .ReceivedAt}}</a></td>
<td>{{.Username}}</td><td>{{.Route}}</td>
<td class="mono">{{.From}}</td><td class="mono">{{.Rcpt}}</td>
<td>{{.Subject}}</td><td class="muted">{{.Size}}</td></tr>{{end}}
</tbody></table>
{{else}}<p class="empty">No messages logged yet.</p>{{end}}
{{template "bottom" .}}{{end}}

{{define "detail"}}{{template "top" .}}
<p style="margin-top:1rem"><a href="/">&larr; all messages</a></p>
<dl class="kv">
<dt>Received</dt><dd class="mono">{{ts .M.ReceivedAt}}</dd>
<dt>User</dt><dd>{{.M.Username}}</dd>
<dt>Route</dt><dd>{{.M.Route}}</dd>
<dt>From (envelope)</dt><dd class="mono">{{.M.From}}</dd>
<dt>To (envelope)</dt><dd class="mono">{{.M.Rcpt}}</dd>
<dt>Remote</dt><dd class="mono">{{.M.RemoteAddr}}</dd>
<dt>Subject</dt><dd>{{.P.Subject}}</dd>
<dt>Size</dt><dd>{{.M.Size}} bytes &middot; <a href="/message/{{.M.ID}}/raw">raw .eml</a></dd>
</dl>
{{if .P.Text}}<h3>Text</h3><pre>{{.P.Text}}</pre>{{end}}
{{if .P.HTML}}<h3>HTML <span class="muted">(source, not rendered)</span></h3><pre>{{.P.HTML}}</pre>{{end}}
{{if .P.Attachments}}<h3>Attachments</h3><table><thead><tr><th>Filename</th><th>Type</th><th>Size</th></tr></thead><tbody>
{{range .P.Attachments}}<tr><td>{{.Filename}}</td><td class="mono">{{.ContentType}}</td><td class="muted">{{len .Content}}</td></tr>{{end}}
</tbody></table>{{end}}
{{template "bottom" .}}{{end}}

{{define "rejections"}}{{template "top" .}}
{{if .Rejections}}<table><thead><tr>
<th>Time</th><th>Stage</th><th>Code</th><th>IP</th><th>User</th><th>From</th><th>To</th><th>Reason</th></tr></thead><tbody>
{{range .Rejections}}<tr>
<td class="mono">{{ts .At}}</td><td>{{.Stage}}</td><td>{{.Code}}</td>
<td class="mono">{{.RemoteAddr}}</td><td>{{.Username}}</td>
<td class="mono">{{.From}}</td><td class="mono">{{.Rcpt}}</td><td>{{.Reason}}</td></tr>{{end}}
</tbody></table>
{{else}}<p class="empty">No rejections recorded.</p>{{end}}
{{template "bottom" .}}{{end}}
`
