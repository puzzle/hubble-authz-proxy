package main

import (
	"errors"
	"net/http"
	"strings"
)

var errNoIdentity = errors.New("no authenticated identity in request")

// Identity is derived from headers injected by oauth2-proxy:
// X-Auth-Request-User / -Email / -Groups.
//
// SECURITY: these headers are trustworthy ONLY if clients cannot reach this
// proxy directly. Enforce that with:
//   - a NetworkPolicy so only the oauth2-proxy / frontend pod can reach the
//     proxy's listen port, and one so only this proxy can reach the ui-backend;
//   - oauth2-proxy configured to STRIP any inbound X-Auth-Request-* headers from
//     the client before setting its own;
//   - optionally, a shared secret header checked here as defence in depth.
type Identity struct {
	User   string
	Email  string
	Groups []string
}

func identityFromRequest(r *http.Request) (Identity, error) {
	id := Identity{
		User:   r.Header.Get("X-Auth-Request-User"),
		Email:  r.Header.Get("X-Auth-Request-Email"),
		Groups: splitGroups(r.Header.Values("X-Auth-Request-Groups")),
	}
	if id.User == "" && id.Email == "" {
		return Identity{}, errNoIdentity
	}
	return id, nil
}

// splitGroups accepts either repeated headers or a single comma-separated one.
func splitGroups(v []string) []string {
	var out []string
	for _, item := range v {
		for _, g := range strings.Split(item, ",") {
			if g = strings.TrimSpace(g); g != "" {
				out = append(out, g)
			}
		}
	}
	return out
}
