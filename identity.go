package main

import (
	"errors"
	"net/http"
	"strings"
)

var errNoIdentity = errors.New("no authenticated identity in request")

// Header families oauth2-proxy can present the caller's identity in. Both use
// the same three suffixes, so a prefix is enough to select between them.
const (
	// AuthRequestPrefix is what oauth2-proxy emits with --set-xauthrequest, and
	// what an nginx auth_request or Traefik forwardAuth copies onto the upstream
	// request. This is the default.
	AuthRequestPrefix = "X-Auth-Request"
	// ForwardedPrefix is what oauth2-proxy emits with --pass-user-headers when
	// it is the reverse proxy itself, as in the sidecar deployment. It is not
	// the default because X-Forwarded-* is a far more common header family that
	// unrelated intermediaries also set, so trusting it must be deliberate.
	ForwardedPrefix = "X-Forwarded"
)

// Identity is derived from the headers whichever component terminated
// authentication put on the request.
//
// SECURITY: these headers are trustworthy ONLY if clients cannot reach this
// proxy directly. Enforce that with:
//   - a NetworkPolicy so only the authenticating component can reach the proxy's
//     listen port, and nothing can reach the ui-backend directly;
//   - an authenticator that overwrites these headers rather than passing a
//     client's own through;
//   - optionally, a shared secret header checked here as defence in depth.
type Identity struct {
	User   string
	Email  string
	Groups []string
}

// identityHeaders names the three headers to read, derived from a prefix.
type identityHeaders struct {
	user, email, groups string
}

func newIdentityHeaders(prefix string) identityHeaders {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "-")
	return identityHeaders{
		user:   prefix + "-User",
		email:  prefix + "-Email",
		groups: prefix + "-Groups",
	}
}

func (h identityHeaders) from(r *http.Request) (Identity, error) {
	id := Identity{
		User:   r.Header.Get(h.user),
		Email:  r.Header.Get(h.email),
		Groups: splitGroups(r.Header.Values(h.groups)),
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
