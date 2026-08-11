package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
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
	a, err := NewStaticAuthorizer(path)
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
		if _, err := identityFromRequest(newReq(http.Header{})); err == nil {
			t.Error("want error when oauth2-proxy headers are absent")
		}
	})

	t.Run("comma-separated groups", func(t *testing.T) {
		id, err := identityFromRequest(newReq(http.Header{
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
		id, err := identityFromRequest(newReq(http.Header{
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
		_, err := identityFromRequest(newReq(http.Header{
			"X-Auth-Request-Email": {"bob@example.com"},
		}))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
