// Package mail parses an accepted SMTP message (envelope + raw DATA) into a
// structured form the bridge can turn into a webhook payload.
package mail

import (
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // register non-UTF-8 charsets
	"github.com/emersion/go-message/mail"
)

// Attachment is a decoded MIME attachment (or inline part with a filename).
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte
}

// Message is a parsed inbound message plus its SMTP envelope.
type Message struct {
	// Envelope (from the SMTP conversation, authoritative for routing).
	From string   // MAIL FROM
	Rcpt []string // RCPT TO (may be several)

	// Parsed from headers/body.
	Subject     string
	Headers     map[string]string
	Text        string
	HTML        string
	Attachments []Attachment

	// Raw is the verbatim DATA payload (RFC 5322 message).
	Raw []byte
}

// Parse builds a Message from the SMTP envelope and raw DATA. Parsing failures
// on the body are tolerated: the raw bytes are always preserved so a message is
// never silently dropped.
func Parse(from string, rcpt []string, raw []byte) *Message {
	m := &Message{
		From:    from,
		Rcpt:    append([]string(nil), rcpt...),
		Headers: map[string]string{},
		Raw:     raw,
	}

	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil {
		return m // keep envelope + raw; body unparseable
	}

	// Flatten headers (last value wins for duplicates).
	fields := entity.Header.Fields()
	for fields.Next() {
		v, err := fields.Text()
		if err != nil {
			v = fields.Value()
		}
		m.Headers[fields.Key()] = v
	}
	m.Subject = m.Headers["Subject"]

	walk(entity, m)
	return m
}

// walk descends the MIME tree collecting text, html, and attachments.
func walk(e *message.Entity, m *Message) {
	if mr := e.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			walk(part, m)
		}
		return
	}

	kind, params, _ := e.Header.ContentType()
	disp, dispParams, _ := parseDisposition(e)
	filename := dispParams["filename"]
	if filename == "" {
		filename = params["name"]
	}

	body, _ := io.ReadAll(e.Body)

	isAttachment := disp == "attachment" || (filename != "" && !strings.HasPrefix(kind, "text/"))
	switch {
	case isAttachment:
		m.Attachments = append(m.Attachments, Attachment{
			Filename:    filename,
			ContentType: kind,
			Content:     body,
		})
	case kind == "text/html":
		if m.HTML == "" {
			m.HTML = string(body)
		}
	case kind == "text/plain" || kind == "":
		if m.Text == "" {
			m.Text = string(body)
		}
	default:
		// Unknown leaf with no disposition: treat as attachment if named, else ignore.
		if filename != "" {
			m.Attachments = append(m.Attachments, Attachment{
				Filename:    filename,
				ContentType: kind,
				Content:     body,
			})
		}
	}
}

func parseDisposition(e *message.Entity) (string, map[string]string, error) {
	disp, params, err := e.Header.ContentDisposition()
	if err != nil {
		return "", map[string]string{}, err
	}
	return disp, params, nil
}

// AddressList parses a header value (e.g. To/From) into plain addresses.
// Best-effort: returns nil on failure.
func AddressList(header string) []string {
	addrs, err := mail.ParseAddressList(header)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Address)
	}
	return out
}
