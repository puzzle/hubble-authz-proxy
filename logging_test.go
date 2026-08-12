package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
)

// testLogger discards output; tests assert on behaviour, not log text.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// A caller disconnecting mid-poll is the normal case here, not a failure: the
// UI holds several long-polls open and aborts them on every reload. Treating
// those as errors buried real problems in noise.
func TestClientGone(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"context canceled", context.Canceled, true},
		{"wrapped context canceled", errors.New("x: " + context.Canceled.Error()), false},
		{"properly wrapped", errWrap(context.Canceled), true},
		{"abort handler", http.ErrAbortHandler, true},
		{"deadline exceeded is a real problem", context.DeadlineExceeded, false},
		{"upstream refused", errors.New("connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientGone(tc.err); got != tc.want {
				t.Errorf("clientGone(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func errWrap(err error) error { return &wrapped{err} }

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "proxying: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }

// A prefix mismatch is the likeliest misconfiguration and produces a bare 401.
// The logs must be able to say "the other family arrived" so it names itself.
func TestIdentityHeaderDiagnostics(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "http://x/api/control-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Forwarded-Email", "bob@example.com")
	r.Header.Set("X-Forwarded-Groups", "team-a")

	h := newIdentityHeaders(AuthRequestPrefix)
	if got := h.presentIn(r); len(got) != 0 {
		t.Errorf("present = %v, want none for the configured family", got)
	}
	other := h.otherFamilyIn(r)
	if len(other) != 2 {
		t.Fatalf("other family = %v, want the two X-Forwarded headers", other)
	}

	// And the reverse, so the diagnostic is not hard-coded one way.
	h2 := newIdentityHeaders(ForwardedPrefix)
	if got := h2.presentIn(r); len(got) != 2 {
		t.Errorf("present = %v, want both configured headers", got)
	}
	if got := h2.otherFamilyIn(r); len(got) != 0 {
		t.Errorf("other family = %v, want none", got)
	}
}
