package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// newLogger builds the process logger. Text by default because these logs are
// usually read with kubectl logs; json for anything shipping them onward.
func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	if strings.EqualFold(format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// clientGone reports whether an error is the caller having disconnected rather
// than the upstream having failed.
//
// The UI long-polls, so a page reload, a navigation or a namespace switch aborts
// several in-flight requests at once; ReverseProxy surfaces each through
// ErrorHandler. Reporting those identically to upstream failures makes both
// useless: one reload looks like three outages, and a real outage looks like a
// reload.
//
// This is a classification, not a reason to ignore them: a rising rate of
// client_gone points at something upstream stalling callers. Individual
// occurrences go to debug to keep per-request noise down; the counter is what
// you alert on.
func clientGone(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, http.ErrAbortHandler)
}

// headerNames lists which of the headers we care about were present, without
// their values. Enough to tell "the authenticator is not configured" from
// "the authenticator sends a different header family", which is the question
// behind almost every "why do I see nothing" report.
func (h identityHeaders) presentIn(r *http.Request) []string {
	var found []string
	for _, name := range []string{h.user, h.email, h.groups} {
		if r.Header.Get(name) != "" {
			found = append(found, name)
		}
	}
	return found
}

// otherFamilyIn reports identity headers from the family we are NOT reading, so
// a prefix misconfiguration names itself in the logs instead of presenting as a
// silent 401.
func (h identityHeaders) otherFamilyIn(r *http.Request) []string {
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

// cmpOr returns the first non-empty string.
func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
