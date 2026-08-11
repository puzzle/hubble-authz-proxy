package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	uipb "github.com/cilium/hubble-ui/backend/proto/ui"
)

// Metric labels must come from a fixed set. Both of these derive from
// caller-reachable input, so an unbounded mapping would let anyone who can
// reach the proxy exhaust its memory with unique time series.
func TestMetricLabelsAreBounded(t *testing.T) {
	t.Run("route", func(t *testing.T) {
		cases := map[string]string{
			"/control-stream":               routeControlStream,
			"control-stream":                routeControlStream,
			"/service-map-stream":           routeServiceMapStre,
			"/../../etc/passwd":             "other",
			"/" + strings.Repeat("x", 4096): "other",
			"":                              "other",
		}
		for in, want := range cases {
			if got := knownRoute(in); got != want {
				t.Errorf("knownRoute(%.20q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("event kind", func(t *testing.T) {
		cases := []struct {
			ev   *uipb.Event
			want string
		}{
			{&uipb.Event{Event: &uipb.Event_Flow{}}, "flow"},
			{&uipb.Event{Event: &uipb.Event_Flows{}}, "flows"},
			{&uipb.Event{Event: &uipb.Event_NamespaceState{}}, "namespace_state"},
			{&uipb.Event{Event: &uipb.Event_ServiceState{}}, "service_state"},
			{&uipb.Event{Event: &uipb.Event_ServiceLinkState{}}, "service_link_state"},
			{&uipb.Event{Event: &uipb.Event_Notification{}}, "notification"},
			{&uipb.Event{}, "unknown"},
		}
		for _, tc := range cases {
			if got := eventKind(tc.ev); got != tc.want {
				t.Errorf("eventKind = %q, want %q", got, tc.want)
			}
		}
	})
}

func TestMetricsHandler(t *testing.T) {
	srv := httptest.NewServer(metricsHandler(metricsRegistry()))
	t.Cleanup(srv.Close)

	t.Run("metrics", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
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
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
}
