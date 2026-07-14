package server

import (
	"errors"

	"github.com/emersion/go-sasl"
)

// loginServer implements the non-standard but widely-used SASL LOGIN mechanism
// server-side (go-sasl only ships the client). It drives the classic
// "Username:" / "Password:" challenge exchange.
type loginServer struct {
	authenticate func(username, password string) error
	username     string
	state        int
}

func newLoginServer(auth func(username, password string) error) sasl.Server {
	return &loginServer{authenticate: auth}
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.state {
	case 0:
		l.state++
		return []byte("Username:"), false, nil
	case 1:
		l.username = string(response)
		l.state++
		return []byte("Password:"), false, nil
	case 2:
		l.state++
		if err := l.authenticate(l.username, string(response)); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	default:
		return nil, false, errors.New("sasl: unexpected LOGIN state")
	}
}
