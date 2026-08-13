package main

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Request outcomes. Declared once and referenced from both the call sites and
// the pre-initialisation below: adding one without exporting it at zero makes
// alerts on it silently useless, which is exactly what happened when
// client_gone and upstream_error were introduced.
const (
	outcomeFiltered        = "filtered"
	outcomeUnauthenticated = "unauthenticated"
	outcomeAuthzError      = "authz_error"
	outcomeClientGone      = "client_gone"
	outcomeUpstreamError   = "upstream_error"
	// responseTooLarge is separate from upstream_error because it is a limit we
	// chose, not a fault: seeing it means --max-response-bytes needs raising, or
	// the cluster outgrew what one response can carry.
	outcomeResponseTooLarge = "response_too_large"
	// passthrough is the one outcome not tied to an API route.
	outcomePassthrough = "passthrough"
	routeNone          = "-"
)

// requestOutcomes is every outcome reported against a route.
var requestOutcomes = []string{
	outcomeFiltered,
	outcomeUnauthenticated,
	outcomeAuthzError,
	outcomeClientGone,
	outcomeUpstreamError,
	outcomeResponseTooLarge,
}

// Metrics are served on their own listener, never on the proxy port. The proxy
// port is the trusted path — reaching it is what authenticates a caller — so
// exposing an unauthenticated /metrics there would widen that surface, and
// scraping it would require Prometheus to be allowed through the NetworkPolicy
// that is supposed to admit only the authenticating pod.
var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hubble_authz_requests_total",
		Help: "Requests handled by the proxy, by API route and outcome.",
	}, []string{"route", "outcome"})

	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "hubble_authz_request_duration_seconds",
		Help: "End-to-end proxy handling time, including the upstream call.",
		// Poll responses are long by design (the backend holds the request open
		// until it has data or hits its poll delay), so the upper buckets are
		// deliberately generous.
		Buckets: []float64{.005, .025, .1, .5, 1, 2.5, 5, 10, 30},
	}, []string{"route"})

	eventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hubble_authz_events_total",
		Help: "Service-map and control-stream events seen, by kind and decision.",
	}, []string{"kind", "decision"})

	scopeResolutionDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hubble_authz_scope_resolution_seconds",
		Help:    "Time to resolve a caller's allowed namespace set.",
		Buckets: []float64{.001, .005, .025, .1, .5, 1, 5},
	}, []string{"mode"})

	scopeCacheTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hubble_authz_scope_cache_total",
		Help: "Scope cache lookups, by result.",
	}, []string{"result"})

	subjectAccessReviewsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hubble_authz_subjectaccessreviews_total",
		Help: "SubjectAccessReviews issued against the API server.",
	})

	trackedChannels = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "hubble_authz_tracked_channels",
		Help: "Client channels with retained service-map state.",
	})

	// A plain Counter, so it exports at zero on registration without needing an
	// entry in initLabelCombinations. Label-free by design: this is a capacity
	// signal, and there is nothing to break it down by that is not either
	// unbounded or caller-controlled.
	channelEvictionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hubble_authz_channel_evictions_total",
		Help: "Live channels dropped to stay under --max-channels. " +
			"Sustained nonzero means the limit is too low for the number of " +
			"concurrent sessions; affected clients briefly lose service-map links.",
	})

	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hubble_authz_build_info",
		Help: "Always 1. Carries the running version as a label.",
	}, []string{"version"})
)

// metricsRegistry is process-local rather than the default registry so tests can
// exercise instrumented code without colliding on duplicate registration.
func metricsRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		requestsTotal,
		requestDuration,
		eventsTotal,
		scopeResolutionDuration,
		scopeCacheTotal,
		subjectAccessReviewsTotal,
		trackedChannels,
		channelEvictionsTotal,
		buildInfo,
	)
	initLabelCombinations()
	// Answers "which version is actually running" from Prometheus alone, which
	// is otherwise only visible by inspecting the pod.
	buildInfo.WithLabelValues(version).Set(1)
	return reg
}

// initLabelCombinations exports every known series at zero.
//
// A *Vec emits nothing until a label combination is first observed, so without
// this a rate() over hubble_authz_events_total{decision="dropped"} returns no
// data rather than 0 until something is actually dropped — which reads as "the
// filter is not running" exactly when it is running correctly.
func initLabelCombinations() {
	for _, route := range knownRoutes {
		for _, outcome := range requestOutcomes {
			requestsTotal.WithLabelValues(route, outcome)
		}
		requestDuration.WithLabelValues(route)
	}
	requestsTotal.WithLabelValues(routeNone, outcomePassthrough)

	kinds := []string{
		"flow", "flows", "namespace_state",
		"service_state", "service_link_state", "notification", "unknown",
	}
	for _, kind := range kinds {
		for _, decision := range []string{"kept", "dropped"} {
			eventsTotal.WithLabelValues(kind, decision)
		}
	}

	for _, result := range []string{"hit", "miss"} {
		scopeCacheTotal.WithLabelValues(result)
	}
	for _, mode := range []string{"static", "rbac"} {
		scopeResolutionDuration.WithLabelValues(mode)
	}
}

func metricsHandler(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// instrumentedAuthorizer times scope resolution regardless of the backing mode.
type instrumentedAuthorizer struct {
	next Authorizer
	mode string
}

func (a instrumentedAuthorizer) AllowedNamespaces(ctx context.Context, id Identity) (Scope, error) {
	timer := prometheus.NewTimer(scopeResolutionDuration.WithLabelValues(a.mode))
	defer timer.ObserveDuration()
	return a.next.AllowedNamespaces(ctx, id)
}
