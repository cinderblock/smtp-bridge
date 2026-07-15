// Package router selects the first configured route matching a recipient.
package router

import (
	"strings"

	"github.com/cinderblock/smtp-bridge/internal/config"
)

// Router matches recipients to routes in configured order.
type Router struct {
	routes []config.Route
}

func New(routes []config.Route) *Router {
	return &Router{routes: routes}
}

// Match returns the first route owned by the authenticated username whose
// recipient conditions match rcpt, and whether one was found. Matching is
// case-insensitive; usernames must match exactly. A route with an empty Match
// block is a catch-all for its owner.
func (r *Router) Match(username, rcpt string) (config.Route, bool) {
	local, domain := split(rcpt)
	localBase := stripTag(local)
	for _, rt := range r.routes {
		if rt.Username != username {
			continue
		}
		if matches(rt.Match, rcpt, localBase, domain) {
			return rt, true
		}
	}
	return config.Route{}, false
}

func matches(m config.Match, rcpt, localBase, domain string) bool {
	if m.Rcpt != "" && !strings.EqualFold(m.Rcpt, rcpt) {
		return false
	}
	if m.RcptDomain != "" && !strings.EqualFold(m.RcptDomain, domain) {
		return false
	}
	if m.RcptLocalpart != "" && !strings.EqualFold(m.RcptLocalpart, localBase) {
		return false
	}
	return true
}

// split separates an address into local and domain (lowercased domain).
func split(addr string) (local, domain string) {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return addr, ""
	}
	return addr[:at], addr[at+1:]
}

// stripTag removes a "+tag" suffix from the local part (subaddressing).
func stripTag(local string) string {
	if i := strings.IndexByte(local, '+'); i >= 0 {
		return local[:i]
	}
	return local
}
