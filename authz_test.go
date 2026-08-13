package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testMapping = `
admins:
  - platform-admins
  - alice@example.com
groupToNamespaces:
  team-payments:
    - payments
    - payments-staging
  team-search:
    - search
userToNamespaces:
  bob@example.com:
    - sandbox-bob
`

func newTestAuthorizer(t *testing.T) *StaticAuthorizer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.yaml")
	if err := os.WriteFile(path, []byte(testMapping), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := NewStaticAuthorizer(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStaticAuthorizer(t *testing.T) {
	a := newTestAuthorizer(t)

	tests := []struct {
		name    string
		id      Identity
		wantAll bool
		wantNS  []string
	}{
		{
			name:    "admin by group",
			id:      Identity{Email: "carol@example.com", Groups: []string{"platform-admins"}},
			wantAll: true,
		},
		{
			name:    "admin by email",
			id:      Identity{Email: "alice@example.com"},
			wantAll: true,
		},
		{
			name:   "group grant",
			id:     Identity{Email: "dave@example.com", Groups: []string{"team-payments"}},
			wantNS: []string{"payments", "payments-staging"},
		},
		{
			name:   "union of two groups",
			id:     Identity{Email: "eve@example.com", Groups: []string{"team-payments", "team-search"}},
			wantNS: []string{"payments", "payments-staging", "search"},
		},
		{
			name:   "per-user grant unions with group grant",
			id:     Identity{Email: "bob@example.com", Groups: []string{"team-search"}},
			wantNS: []string{"sandbox-bob", "search"},
		},
		{
			// The important negative: an unknown caller gets an empty scope, not a
			// wide one, and is not silently promoted to admin.
			name:   "unknown identity gets nothing",
			id:     Identity{Email: "mallory@example.com", Groups: []string{"not-a-real-group"}},
			wantNS: nil,
		},
		{
			// An identity with no user/email must not match admin entries via the
			// empty string.
			name:   "empty identity gets nothing",
			id:     Identity{},
			wantNS: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.AllowedNamespaces(context.Background(), tc.id)
			if err != nil {
				t.Fatal(err)
			}
			if got.All != tc.wantAll {
				t.Fatalf("All = %v, want %v", got.All, tc.wantAll)
			}
			if tc.wantAll {
				return
			}
			if len(got.Namespaces) != len(tc.wantNS) {
				t.Fatalf("namespaces = %v, want %v", got.Namespaces, tc.wantNS)
			}
			for _, ns := range tc.wantNS {
				if !got.Namespaces[ns] {
					t.Errorf("missing namespace %q in %v", ns, got.Namespaces)
				}
			}
		})
	}
}

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
		if _, err := newIdentityHeaders(AuthRequestPrefix).from(newReq(http.Header{})); err == nil {
			t.Error("want error when oauth2-proxy headers are absent")
		}
	})

	t.Run("comma-separated groups", func(t *testing.T) {
		id, err := newIdentityHeaders(AuthRequestPrefix).from(newReq(http.Header{
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
		id, err := newIdentityHeaders(AuthRequestPrefix).from(newReq(http.Header{
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
		_, err := newIdentityHeaders(AuthRequestPrefix).from(newReq(http.Header{
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
		id, err := newIdentityHeaders(ForwardedPrefix).from(newReq(forwarded))
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
		if _, err := newIdentityHeaders(AuthRequestPrefix).from(newReq(forwarded)); err == nil {
			t.Error("X-Forwarded-* was accepted by the X-Auth-Request default")
		}
	})

	t.Run("a trailing dash in the prefix is tolerated", func(t *testing.T) {
		id, err := newIdentityHeaders("X-Forwarded-").from(newReq(forwarded))
		if err != nil || id.Email != "bob@example.com" {
			t.Errorf("got %+v, %v", id, err)
		}
	})
}

// --- hot reload -------------------------------------------------------------

// writeMapping replaces the file the way an editor or kubelet would, rather than
// appending, so the authorizer sees a whole new document.
func writeMapping(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newReloadableAuthorizer(t *testing.T, content string) (*StaticAuthorizer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.yaml")
	writeMapping(t, path, content)
	a, err := NewStaticAuthorizer(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return a, path
}

func nsOf(t *testing.T, a *StaticAuthorizer, id Identity) map[string]bool {
	t.Helper()
	scope, err := a.AllowedNamespaces(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return scope.Namespaces
}

// The whole point: an operator edits the ConfigMap and the change takes effect
// without a restart. Previously the file changed under a running pod and the
// proxy went on using the mapping it read at startup.
func TestMappingReloadPicksUpGrants(t *testing.T) {
	a, path := newReloadableAuthorizer(t, `
groupToNamespaces:
  team-payments:
    - payments
`)
	id := Identity{Email: "bob@example.com", Groups: []string{"team-payments"}}

	if ns := nsOf(t, a, id); !ns["payments"] || ns["search"] {
		t.Fatalf("initial scope wrong: %v", ns)
	}

	writeMapping(t, path, `
groupToNamespaces:
  team-payments:
    - payments
    - search
`)
	changed, err := a.reload()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("reload did not notice the edit")
	}
	if ns := nsOf(t, a, id); !ns["payments"] || !ns["search"] {
		t.Errorf("grant did not take effect: %v", ns)
	}
}

// Revocation is the direction that matters: a stale mapping means access someone
// believes they removed is still in force.
func TestMappingReloadAppliesRevocation(t *testing.T) {
	a, path := newReloadableAuthorizer(t, `
admins:
  - alice@example.com
groupToNamespaces:
  team-payments:
    - payments
`)
	alice := Identity{Email: "alice@example.com"}
	bob := Identity{Email: "bob@example.com", Groups: []string{"team-payments"}}

	if scope, _ := a.AllowedNamespaces(context.Background(), alice); !scope.All {
		t.Fatal("alice did not start as an admin")
	}

	writeMapping(t, path, `groupToNamespaces: {}`)
	if _, err := a.reload(); err != nil {
		t.Fatal(err)
	}

	if scope, _ := a.AllowedNamespaces(context.Background(), alice); scope.All {
		t.Error("admin rights survived their removal from the mapping")
	}
	if ns := nsOf(t, a, bob); len(ns) != 0 {
		t.Errorf("revoked namespaces are still granted: %v", ns)
	}
}

// A half-written or malformed file must not become a cluster-wide lockout. The
// file is written by something else while we read it, so a torn read is a normal
// event, not an exceptional one.
func TestMappingReloadKeepsLastGoodOnParseError(t *testing.T) {
	a, path := newReloadableAuthorizer(t, `
groupToNamespaces:
  team-payments:
    - payments
`)
	id := Identity{Groups: []string{"team-payments"}}

	writeMapping(t, path, "groupToNamespaces: [this is not: a map")
	changed, err := a.reload()
	if err == nil {
		t.Fatal("a malformed mapping was accepted")
	}
	if changed {
		t.Error("reported a change it could not apply")
	}
	if ns := nsOf(t, a, id); !ns["payments"] {
		t.Errorf("a bad edit revoked live access: %v", ns)
	}

	// And it must recover once the file is valid again, without a restart.
	writeMapping(t, path, `
groupToNamespaces:
  team-payments:
    - payments-v2
`)
	if _, err := a.reload(); err != nil {
		t.Fatal(err)
	}
	if ns := nsOf(t, a, id); !ns["payments-v2"] {
		t.Errorf("did not recover after the file was fixed: %v", ns)
	}
}

// Same for the file disappearing, which happens mid-swap on some volume types.
func TestMappingReloadKeepsLastGoodOnReadError(t *testing.T) {
	a, path := newReloadableAuthorizer(t, `
groupToNamespaces:
  team-payments:
    - payments
`)
	id := Identity{Groups: []string{"team-payments"}}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := a.reload(); err == nil {
		t.Fatal("a missing mapping file was accepted")
	}
	if ns := nsOf(t, a, id); !ns["payments"] {
		t.Errorf("a missing file revoked live access: %v", ns)
	}
}

// Rewriting a ConfigMap with identical content is routine (any resync), and must
// not be reported as a change — that is the signal an operator reads as "someone
// edited access".
func TestMappingReloadIgnoresIdenticalContent(t *testing.T) {
	a, path := newReloadableAuthorizer(t, testMapping)

	writeMapping(t, path, testMapping)
	changed, err := a.reload()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("identical content was reported as a change")
	}
}

// A bad mapping at startup must be fatal: coming up with none would silently
// deny everyone, which looks like an outage with no cause.
func TestStaticAuthorizerRefusesToStartOnBadMapping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapping.yaml")
	writeMapping(t, path, "admins: [unterminated")

	if _, err := NewStaticAuthorizer(path, testLogger()); err == nil {
		t.Error("started with an unparseable mapping")
	}
}

// The reloader has to survive a bad file rather than exit, or the first typo
// silently ends hot-reload for the life of the pod.
func TestRunReloaderSurvivesErrorsAndStopsOnContextCancel(t *testing.T) {
	a, path := newReloadableAuthorizer(t, `
groupToNamespaces:
  team-payments:
    - payments
`)
	id := Identity{Groups: []string{"team-payments"}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.RunReloader(ctx, time.Millisecond) }()

	writeMapping(t, path, "not: [valid")
	time.Sleep(30 * time.Millisecond)

	// Still serving the last good mapping, and still running.
	if ns := nsOf(t, a, id); !ns["payments"] {
		t.Errorf("last good mapping was lost: %v", ns)
	}

	writeMapping(t, path, `
groupToNamespaces:
  team-payments:
    - payments-v2
`)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if nsOf(t, a, id)["payments-v2"] {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ns := nsOf(t, a, id); !ns["payments-v2"] {
		t.Errorf("reloader stopped after an error: %v", ns)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("reloader did not stop on context cancellation")
	}
}

// A zero interval must not spin: it means "disabled", not "as fast as possible".
func TestRunReloaderZeroIntervalReturns(t *testing.T) {
	a, _ := newReloadableAuthorizer(t, testMapping)

	done := make(chan struct{})
	go func() { defer close(done); a.RunReloader(context.Background(), 0) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("a zero interval left the reloader running")
	}
}
