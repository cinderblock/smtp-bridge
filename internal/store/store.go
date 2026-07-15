// Package store persists the message log (opt-out) and the durable async
// delivery queue, both backed by a single pure-Go SQLite database.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database.
type Store struct {
	db            *sql.DB
	logContent    bool
	logRejections bool
}

// Open opens (creating if needed) the database at path and runs migrations.
// logContent controls whether message bodies/metadata are written to the log;
// logRejections controls whether rejected requests are persisted for later
// inspection (envelope metadata only — no message bodies).
func Open(path string, logContent, logRejections bool) (*Store, error) {
	// Busy timeout + WAL keep the single-writer queue smooth under concurrency.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // serialize writes; SQLite is single-writer
	s := &Store{db: db, logContent: logContent, logRejections: logRejections}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS messages (
	id           TEXT PRIMARY KEY,
	received_at  INTEGER NOT NULL,
	from_addr    TEXT NOT NULL,
	rcpt         TEXT NOT NULL,
	route        TEXT,
	subject      TEXT,
	size         INTEGER NOT NULL,
	remote_addr  TEXT,
	username     TEXT,
	raw          BLOB
);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at);

CREATE TABLE IF NOT EXISTS deliveries (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	message_id   TEXT NOT NULL,
	route        TEXT NOT NULL,
	attempt      INTEGER NOT NULL,
	attempted_at INTEGER NOT NULL,
	status_code  INTEGER,
	success      INTEGER NOT NULL,
	error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_deliveries_message ON deliveries(message_id);

CREATE TABLE IF NOT EXISTS queue (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	message_id      TEXT NOT NULL,
	route           TEXT NOT NULL,
	payload         BLOB NOT NULL,
	attempts        INTEGER NOT NULL DEFAULT 0,
	next_attempt_at INTEGER NOT NULL,
	created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queue_next ON queue(next_attempt_at);

CREATE TABLE IF NOT EXISTS rejections (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	at          INTEGER NOT NULL,
	stage       TEXT NOT NULL,
	code        INTEGER,
	remote_addr TEXT,
	username    TEXT,
	from_addr   TEXT,
	rcpt        TEXT,
	reason      TEXT
);
CREATE INDEX IF NOT EXISTS idx_rejections_at ON rejections(at);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// MessageLog is a row to persist about an accepted message.
type MessageLog struct {
	ID         string
	ReceivedAt time.Time
	From       string
	Rcpt       []string
	Route      string
	Subject    string
	Size       int
	RemoteAddr string
	Username   string
	Raw        []byte // persisted only when content logging is enabled
}

// LogMessage records an accepted message. It is a no-op (returns nil) when
// content logging is disabled.
func (s *Store) LogMessage(m MessageLog) error {
	if !s.logContent {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO messages
		 (id, received_at, from_addr, rcpt, route, subject, size, remote_addr, username, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		m.ID, m.ReceivedAt.UnixMilli(), m.From, strings.Join(m.Rcpt, ", "),
		m.Route, m.Subject, m.Size, m.RemoteAddr, m.Username, m.Raw,
	)
	if err != nil {
		return fmt.Errorf("log message: %w", err)
	}
	return nil
}

// DeliveryLog records the outcome of one webhook attempt. No-op when content
// logging is disabled.
func (s *Store) LogDelivery(messageID, route string, attempt, statusCode int, success bool, errMsg string) error {
	if !s.logContent {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT INTO deliveries (message_id, route, attempt, attempted_at, status_code, success, error)
		 VALUES (?,?,?,?,?,?,?)`,
		messageID, route, attempt, time.Now().UnixMilli(), statusCode, boolToInt(success), errMsg,
	)
	return err
}

// MessageSummary is a stored message's metadata (no body), for listing.
type MessageSummary struct {
	ID         string
	ReceivedAt time.Time
	From       string
	Rcpt       string
	Route      string
	Subject    string
	Size       int
	Username   string
}

// RecentMessages returns up to limit logged messages, most recent first. Empty
// when content logging is disabled (nothing is stored).
func (s *Store) RecentMessages(limit int) ([]MessageSummary, error) {
	rows, err := s.db.Query(
		`SELECT id, received_at, from_addr, rcpt, route, subject, size, username
		 FROM messages ORDER BY received_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MessageSummary
	for rows.Next() {
		var m MessageSummary
		var atMillis int64
		if err := rows.Scan(&m.ID, &atMillis, &m.From, &m.Rcpt, &m.Route, &m.Subject, &m.Size, &m.Username); err != nil {
			return nil, err
		}
		m.ReceivedAt = time.UnixMilli(atMillis)
		out = append(out, m)
	}
	return out, rows.Err()
}

// Rejection records a request the server refused, for later debugging.
type Rejection struct {
	At         time.Time
	Stage      string // connect | auth | mail | rcpt | data
	Code       int    // SMTP reply code
	RemoteAddr string
	Username   string
	From       string
	Rcpt       string
	Reason     string
}

// LogRejection persists a rejected request. It is a no-op when rejection
// logging is disabled. Independent of message-content logging.
func (s *Store) LogRejection(r Rejection) error {
	if !s.logRejections {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT INTO rejections (at, stage, code, remote_addr, username, from_addr, rcpt, reason)
		 VALUES (?,?,?,?,?,?,?,?)`,
		r.At.UnixMilli(), r.Stage, r.Code, r.RemoteAddr, r.Username, r.From, r.Rcpt, r.Reason,
	)
	if err != nil {
		return fmt.Errorf("log rejection: %w", err)
	}
	return nil
}

// RecentRejections returns up to limit rejections, most recent first.
func (s *Store) RecentRejections(limit int) ([]Rejection, error) {
	rows, err := s.db.Query(
		`SELECT at, stage, code, remote_addr, username, from_addr, rcpt, reason
		 FROM rejections ORDER BY at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rejection
	for rows.Next() {
		var r Rejection
		var atMillis int64
		if err := rows.Scan(&atMillis, &r.Stage, &r.Code, &r.RemoteAddr, &r.Username, &r.From, &r.Rcpt, &r.Reason); err != nil {
			return nil, err
		}
		r.At = time.UnixMilli(atMillis)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Job is a queued async delivery.
type Job struct {
	ID        int64
	MessageID string
	Route     string
	Payload   []byte
	Attempts  int
}

// Enqueue adds a delivery job due immediately.
func (s *Store) Enqueue(messageID, route string, payload []byte) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(
		`INSERT INTO queue (message_id, route, payload, attempts, next_attempt_at, created_at)
		 VALUES (?,?,?,0,?,?)`,
		messageID, route, payload, now, now,
	)
	if err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	return nil
}

// ClaimDue returns up to limit jobs whose next_attempt_at has passed.
func (s *Store) ClaimDue(limit int) ([]Job, error) {
	rows, err := s.db.Query(
		`SELECT id, message_id, route, payload, attempts FROM queue
		 WHERE next_attempt_at <= ? ORDER BY next_attempt_at ASC LIMIT ?`,
		time.Now().UnixMilli(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.MessageID, &j.Route, &j.Payload, &j.Attempts); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// CompleteJob removes a finished (delivered or permanently failed) job.
func (s *Store) CompleteJob(id int64) error {
	_, err := s.db.Exec(`DELETE FROM queue WHERE id = ?`, id)
	return err
}

// RescheduleJob bumps a job's attempt count and next attempt time.
func (s *Store) RescheduleJob(id int64, attempts int, next time.Time) error {
	_, err := s.db.Exec(
		`UPDATE queue SET attempts = ?, next_attempt_at = ? WHERE id = ?`,
		attempts, next.UnixMilli(), id,
	)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
