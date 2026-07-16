package server

import "testing"

// drive runs the loginServer through a sequence of client responses and returns
// the credentials it ultimately authenticated with (or the auth error).
func drive(responses [][]byte) (user, pass string, authErr error, protoErr error, done bool) {
	l := newLoginServer(func(u, p string) error {
		user, pass = u, p
		return authErr
	})
	for _, r := range responses {
		_, done, protoErr = l.Next(r)
		if protoErr != nil || done {
			break
		}
	}
	return
}

// Standard prompted flow: AUTH LOGIN, then username, then password.
func TestLoginPromptedFlow(t *testing.T) {
	u, p, _, protoErr, done := drive([][]byte{nil, []byte("alice"), []byte("s3cret")})
	if protoErr != nil || !done {
		t.Fatalf("prompted flow not completed: done=%v err=%v", done, protoErr)
	}
	if u != "alice" || p != "s3cret" {
		t.Errorf("prompted flow got %q/%q, want alice/s3cret", u, p)
	}
}

// Initial-response flow: AUTH LOGIN <username>, then password. This is the form
// that previously desynced (password was read as the username).
func TestLoginInitialResponseFlow(t *testing.T) {
	u, p, _, protoErr, done := drive([][]byte{[]byte("alice"), []byte("s3cret")})
	if protoErr != nil || !done {
		t.Fatalf("initial-response flow not completed: done=%v err=%v", done, protoErr)
	}
	if u != "alice" || p != "s3cret" {
		t.Errorf("initial-response flow got %q/%q, want alice/s3cret — the username must not be the password", u, p)
	}
}
