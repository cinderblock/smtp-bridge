package router

import "testing"

import "github.com/cinderblock/smtp-bridge/internal/config"

func TestMatch(t *testing.T) {
	routes := []config.Route{
		{Name: "exact", Match: config.Match{Rcpt: "ops@hooks.example.com"}},
		{Name: "local", Match: config.Match{RcptLocalpart: "alerts"}},
		{Name: "domain", Match: config.Match{RcptDomain: "hooks.example.com"}},
		{Name: "catchall"}, // empty match = catch-all
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
		got, ok := r.Match(c.rcpt)
		if !ok {
			t.Errorf("Match(%q): no match, want %q", c.rcpt, c.want)
			continue
		}
		if got.Name != c.want {
			t.Errorf("Match(%q) = %q, want %q", c.rcpt, got.Name, c.want)
		}
	}
}

func TestNoMatchWithoutCatchall(t *testing.T) {
	r := New([]config.Route{{Name: "domain", Match: config.Match{RcptDomain: "hooks.example.com"}}})
	if _, ok := r.Match("nobody@elsewhere.net"); ok {
		t.Error("expected no match for unrouted recipient")
	}
}
