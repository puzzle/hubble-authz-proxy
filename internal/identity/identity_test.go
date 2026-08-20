package identity

import (
	"net/http"
	"testing"
)

func TestIdentityFromRequest(t *testing.T) {
	newReq := func(h http.Header) *http.Request {
		r, err := http.NewRequest(http.MethodPost, "http://x/api/control-stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header = h
		return r
	}

	t.Run("no identity headers is rejected", func(t *testing.T) {
		if _, err := NewHeaders(AuthRequestPrefix).From(newReq(http.Header{})); err == nil {
			t.Error("want error when oauth2-proxy headers are absent")
		}
	})

	t.Run("comma-separated groups", func(t *testing.T) {
		id, err := NewHeaders(AuthRequestPrefix).From(newReq(http.Header{
			"X-Auth-Request-User":   {"bob"},
			"X-Auth-Request-Email":  {"bob@example.com"},
			"X-Auth-Request-Groups": {"team-payments, team-search"},
		}))
		if err != nil {
			t.Fatal(err)
		}
		if id.User != "bob" || id.Email != "bob@example.com" {
			t.Errorf("got %+v", id)
		}
		// oauth2-proxy pads with spaces after commas; those must not become part
		// of the group name or every mapping lookup silently misses.
		if len(id.Groups) != 2 || id.Groups[0] != "team-payments" || id.Groups[1] != "team-search" {
			t.Errorf("groups = %q, want [team-payments team-search]", id.Groups)
		}
	})

	t.Run("repeated group headers", func(t *testing.T) {
		id, err := NewHeaders(AuthRequestPrefix).From(newReq(http.Header{
			"X-Auth-Request-Email":  {"bob@example.com"},
			"X-Auth-Request-Groups": {"team-payments", "team-search"},
		}))
		if err != nil {
			t.Fatal(err)
		}
		if len(id.Groups) != 2 {
			t.Errorf("groups = %q, want 2 entries", id.Groups)
		}
	})

	t.Run("email alone is enough", func(t *testing.T) {
		_, err := NewHeaders(AuthRequestPrefix).From(newReq(http.Header{
			"X-Auth-Request-Email": {"bob@example.com"},
		}))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// oauth2-proxy presents the identity in a different header family depending on
// how it is deployed: X-Auth-Request-* when something else (nginx auth_request,
// Traefik forwardAuth) does the subrequest, X-Forwarded-* when oauth2-proxy is
// itself the reverse proxy, as in the sidecar setup. Both suffixes match, so a
// prefix selects between them.
func TestIdentityHeaderFamilies(t *testing.T) {
	newReq := func(h http.Header) *http.Request {
		r, err := http.NewRequest(http.MethodPost, "http://x/api/control-stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header = h
		return r
	}

	forwarded := http.Header{
		"X-Forwarded-Email":  {"bob@example.com"},
		"X-Forwarded-Groups": {"team-a,team-b"},
	}

	t.Run("forwarded prefix reads them", func(t *testing.T) {
		id, err := NewHeaders(ForwardedPrefix).From(newReq(forwarded))
		if err != nil {
			t.Fatal(err)
		}
		if id.Email != "bob@example.com" || len(id.Groups) != 2 {
			t.Errorf("got %+v", id)
		}
	})

	// The default must NOT read X-Forwarded-*. That family is set by all kinds of
	// intermediaries, so trusting it has to be a deliberate configuration choice
	// rather than something that happens to work.
	t.Run("default ignores forwarded headers", func(t *testing.T) {
		if _, err := NewHeaders(AuthRequestPrefix).From(newReq(forwarded)); err == nil {
			t.Error("X-Forwarded-* was accepted by the X-Auth-Request default")
		}
	})

	t.Run("a trailing dash in the prefix is tolerated", func(t *testing.T) {
		id, err := NewHeaders("X-Forwarded-").From(newReq(forwarded))
		if err != nil || id.Email != "bob@example.com" {
			t.Errorf("got %+v, %v", id, err)
		}
	})
}

// --- hot reload -------------------------------------------------------------
// A prefix mismatch is the likeliest misconfiguration and produces a bare 401.
// The logs must be able to say "the other family arrived" so it names itself.
func TestIdentityHeaderDiagnostics(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "http://x/api/control-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Forwarded-Email", "bob@example.com")
	r.Header.Set("X-Forwarded-Groups", "team-a")

	h := NewHeaders(AuthRequestPrefix)
	if got := h.PresentIn(r); len(got) != 0 {
		t.Errorf("present = %v, want none for the configured family", got)
	}
	other := h.OtherFamilyIn(r)
	if len(other) != 2 {
		t.Fatalf("other family = %v, want the two X-Forwarded headers", other)
	}

	// And the reverse, so the diagnostic is not hard-coded one way.
	h2 := NewHeaders(ForwardedPrefix)
	if got := h2.PresentIn(r); len(got) != 2 {
		t.Errorf("present = %v, want both configured headers", got)
	}
	if got := h2.OtherFamilyIn(r); len(got) != 0 {
		t.Errorf("other family = %v, want none", got)
	}
}
