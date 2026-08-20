package rbac

import (
	"io"
	"log/slog"
)

// testLogger discards output; tests assert on behaviour, not log text.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
