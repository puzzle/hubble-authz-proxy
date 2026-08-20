// Package identity derives the caller from the headers whichever component
// terminated authentication put on the request.
package identity

import (
	"errors"
	"net/http"
	"strings"
)

// ErrNoIdentity means the request carried no identity headers at all, which
// is a misconfigured authenticator rather than a caller with no access.
var ErrNoIdentity = errors.New("no authenticated identity in request")

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

// Headers names the three headers to read, derived from a prefix.
type Headers struct {
	user, email, groups string
}

// NewHeaders derives the three header names to read from a family prefix.
func NewHeaders(prefix string) Headers {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "-")
	return Headers{
		user:   prefix + "-User",
		email:  prefix + "-Email",
		groups: prefix + "-Groups",
	}
}

// Expecting names the header family this reads, for the log line explaining a
// 401. It lives here rather than being formatted at the call site because the
// field names are unexported: which headers a family covers is this type's
// business, not its caller's.
func (h Headers) Expecting() string {
	return h.email + " (and -User/-Groups)"
}

// From reads the caller identity off a request, or ErrNoIdentity if neither a
// user nor an email is present.
func (h Headers) From(r *http.Request) (Identity, error) {
	id := Identity{
		User:   r.Header.Get(h.user),
		Email:  r.Header.Get(h.email),
		Groups: splitGroups(r.Header.Values(h.groups)),
	}
	if id.User == "" && id.Email == "" {
		return Identity{}, ErrNoIdentity
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

// PresentIn lists which of the headers we care about were present, without
// their values. Enough to tell "the authenticator is not configured" from
// "the authenticator sends a different header family", which is the question
// behind almost every "why do I see nothing" report.
func (h Headers) PresentIn(r *http.Request) []string {
	var found []string
	for _, name := range []string{h.user, h.email, h.groups} {
		if r.Header.Get(name) != "" {
			found = append(found, name)
		}
	}
	return found
}

// OtherFamilyIn reports identity headers from the family we are NOT reading, so
// a prefix misconfiguration names itself in the logs instead of presenting as a
// silent 401.
func (h Headers) OtherFamilyIn(r *http.Request) []string {
	other := AuthRequestPrefix
	if strings.HasPrefix(h.email, AuthRequestPrefix) {
		other = ForwardedPrefix
	}
	var found []string
	for _, suffix := range []string{"-User", "-Email", "-Groups"} {
		if name := other + suffix; r.Header.Get(name) != "" {
			found = append(found, name)
		}
	}
	return found
}
