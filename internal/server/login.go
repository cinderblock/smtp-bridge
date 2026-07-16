package server

import "github.com/emersion/go-sasl"

// loginServer implements the non-standard but widely-used SASL LOGIN mechanism
// server-side (go-sasl only ships the client). It drives the classic
// "Username:" / "Password:" challenge exchange, and also accepts the common
// variant where the client supplies the username as an initial response with
// the AUTH command (`AUTH LOGIN <base64 username>`) — many mail clients and
// embedded devices do this, and mishandling it desyncs the exchange.
type loginServer struct {
	authenticate func(username, password string) error
	username     string
	haveUser     bool
}

func newLoginServer(auth func(username, password string) error) sasl.Server {
	return &loginServer{authenticate: auth}
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	if !l.haveUser {
		// First step: the username may arrive as an initial response with the
		// AUTH command (`AUTH LOGIN <base64 username>`); otherwise prompt for it.
		if len(response) == 0 {
			return []byte("Username:"), false, nil
		}
		l.username = string(response)
		l.haveUser = true
		return []byte("Password:"), false, nil
	}
	// Second step: this response is the password.
	if err := l.authenticate(l.username, string(response)); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}
