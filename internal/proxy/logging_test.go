package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
)

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

// testLogger discards output; tests assert on behaviour, not log text.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// testMaxResponse is generous: tests that care about the limit set their own.
const testMaxResponse = 8 << 20
