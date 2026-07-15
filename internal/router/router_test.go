package router

import "testing"

import "github.com/cinderblock/smtp-bridge/internal/config"

func TestMatch(t *testing.T) {
	// All owned by user "u"; matching precedence is by recipient within the user.
	routes := []config.Route{
		{Name: "exact", Username: "u", Match: config.Match{Rcpt: "ops@hooks.example.com"}},
		{Name: "local", Username: "u", Match: config.Match{RcptLocalpart: "alerts"}},
		{Name: "domain", Username: "u", Match: config.Match{RcptDomain: "hooks.example.com"}},
		{Name: "catchall", Username: "u"}, // empty match = catch-all for this user
	}
	r := New(routes)

	cases := []struct {
		rcpt string
		want string
	}{
		{"ops@hooks.example.com", "exact"},    // exact wins (first in order)
		{"alerts@anything.net", "local"},      // local-part match
		{"alerts+prod@anything.net", "local"}, // +tag stripped
		{"team@hooks.example.com", "domain"},  // domain match
		{"TEAM@HOOKS.EXAMPLE.COM", "domain"},  // case-insensitive
		{"random@somewhere.org", "catchall"},  // falls through to catch-all
	}
	for _, c := range cases {
		got, ok := r.Match("u", c.rcpt)
		if !ok {
			t.Errorf("Match(%q): no match, want %q", c.rcpt, c.want)
			continue
		}
		if got.Name != c.want {
			t.Errorf("Match(%q) = %q, want %q", c.rcpt, got.Name, c.want)
		}
	}
}

func TestMatchIsScopedToUser(t *testing.T) {
	routes := []config.Route{
		{Name: "alice-route", Username: "alice", Match: config.Match{RcptDomain: "hooks.example.com"}},
	}
	r := New(routes)
	// Alice's own recipient matches.
	if _, ok := r.Match("alice", "x@hooks.example.com"); !ok {
		t.Error("alice should match her own route")
	}
	// A different user does NOT get alice's route, even for the same recipient.
	if _, ok := r.Match("bob", "x@hooks.example.com"); ok {
		t.Error("bob must not match alice's route")
	}
}

func TestNoMatchWithoutCatchall(t *testing.T) {
	r := New([]config.Route{{Name: "domain", Username: "u", Match: config.Match{RcptDomain: "hooks.example.com"}}})
	if _, ok := r.Match("u", "nobody@elsewhere.net"); ok {
		t.Error("expected no match for unrouted recipient")
	}
}
