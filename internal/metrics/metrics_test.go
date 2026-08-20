package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testRoutes stands in for the real route list, which belongs to the component
// that dispatches on it (internal/proxy) and cannot be imported here without
// recreating the cycle NewRegistry's parameters exist to break. What this file
// verifies is that NewRegistry pre-initialises whatever routes it is handed;
// that the real list is complete is asserted proxy-side, next to knownRoute.
var testRoutes = []string{"control-stream", "service-map-stream", "other"}

func TestMetricsHandler(t *testing.T) {
	srv := httptest.NewServer(Handler(NewRegistry("test", testRoutes)))
	t.Cleanup(srv.Close)

	t.Run("metrics", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"hubble_authz_requests_total",
			"hubble_authz_events_total",
			"hubble_authz_scope_cache_total",
			"hubble_authz_tracked_channels",
		} {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s not exposed", want)
			}
		}
	})

	t.Run("healthz", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
}

// Every outcome the proxy can report must be exported at zero on startup.
//
// A *Vec emits nothing until a label combination is first observed, so an
// outcome that is only created on first occurrence cannot be alerted on: a
// rate() over it returns no data rather than 0, and the series appears at the
// exact moment you would have wanted the alert to already exist. client_gone
// and upstream_error shipped that way, which is what this guards.
func TestEveryOutcomeIsPreInitialised(t *testing.T) {
	reg := NewRegistry("test", testRoutes)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]map[string]bool{}
	for _, f := range families {
		if f.GetName() != "hubble_authz_requests_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			var route, outcome string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "route":
					route = l.GetValue()
				case "outcome":
					outcome = l.GetValue()
				}
			}
			if seen[route] == nil {
				seen[route] = map[string]bool{}
			}
			seen[route][outcome] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("hubble_authz_requests_total was not exported at all")
	}

	for _, route := range testRoutes {
		for _, outcome := range RequestOutcomes {
			if !seen[route][outcome] {
				t.Errorf("route=%q outcome=%q is never exported; an alert on it "+
					"would return no data until the first occurrence", route, outcome)
			}
		}
	}
	if !seen[RouteNone][OutcomePassthrough] {
		t.Errorf("route=%q outcome=%q is never exported", RouteNone, OutcomePassthrough)
	}
}
