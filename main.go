// Command hubble-authz-proxy sits between the Hubble UI frontend and the
// unmodified hubble-ui backend, and enforces per-user, namespace-scoped access
// to what the UI displays. Authentication is expected to be terminated upstream
// by oauth2-proxy, which injects the caller's identity as X-Auth-Request-*
// headers; this process only does *authorization* (namespace filtering).
//
// Data path once deployed:
//
//	browser -> oauth2-proxy -> hubble-ui frontend (nginx, /api)
//	        -> THIS PROXY -> hubble-ui-backend -> hubble-relay
//
// The backend is used as-is: it keeps doing the service-map aggregation, the
// namespace watching and the relay connection. This proxy only unwraps the
// backend's customprotocol responses and removes what the caller may not see.
//
// Deployment: point the frontend's /api at this proxy instead of the backend,
// and use a NetworkPolicy so that only this proxy can reach the backend (and
// only the frontend can reach this proxy). Without that, the backend remains
// reachable unfiltered and the X-Auth-Request-* headers are spoofable.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"syscall"
	"time"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		listen        = flag.String("listen", ":8090", "address the Hubble UI frontend proxies /api to")
		metricsListen = flag.String("metrics-listen", ":9090", "address serving /metrics and /healthz; empty disables it")
		backendURL    = flag.String("backend", "http://hubble-ui-backend:8090", "upstream hubble-ui backend base URL")
		apiPrefix     = flag.String("api-prefix", "/api", "path prefix carrying backend routes; everything else is passed through")
		identityPfx   = flag.String("identity-header-prefix", AuthRequestPrefix,
			"header family carrying the caller identity: X-Auth-Request (nginx auth_request / Traefik forwardAuth) or X-Forwarded (oauth2-proxy as the reverse proxy)")
		mode          = flag.String("authz", "static", "authorization backend: static | rbac")
		mapFile       = flag.String("authz-config", "/etc/hubble-authz/mapping.yaml", "static mode: group/user -> namespace mapping")
		rbacTTL       = flag.Duration("rbac-ttl", 60*time.Second, "rbac mode: cache TTL for a caller's resolved namespace set")
		rbacWorkers   = flag.Int("rbac-concurrency", 16, "rbac mode: SubjectAccessReviews issued in parallel per resolution")
		channelTTL    = flag.Duration("channel-ttl", 10*time.Minute, "how long to keep per-channel service-map state after a client goes idle")
		reqBoth       = flag.Bool("require-both-endpoints", false, "only show traffic when BOTH endpoints are in allowed namespaces (stricter)")
		shutdownGrace = flag.Duration("shutdown-timeout", 20*time.Second, "how long to let in-flight requests finish after SIGTERM")
	)
	flag.Parse()

	backend, err := url.Parse(*backendURL)
	if err != nil {
		log.Fatalf("parse -backend: %v", err)
	}
	if backend.Scheme == "" || backend.Host == "" {
		log.Fatalf("-backend must be an absolute URL, got %q", *backendURL)
	}

	// Cancelled on SIGTERM/SIGINT. Kubernetes sends SIGTERM and then removes the
	// pod from Service endpoints, so draining matters here: the UI holds long
	// poll requests open, and killing them mid-flight surfaces as errors in the
	// browser during every rollout.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var authz Authorizer
	switch *mode {
	case "static":
		authz, err = NewStaticAuthorizer(*mapFile)
	case "rbac":
		var rbacAuthz *RBACAuthorizer
		rbacAuthz, err = NewRBACAuthorizer(*rbacTTL, *rbacWorkers)
		if err == nil {
			go rbacAuthz.RunSweeper(ctx)
			authz = rbacAuthz
		}
	default:
		err = errors.New("unknown -authz mode (want static|rbac)")
	}
	if err != nil {
		log.Fatalf("authorizer: %v", err)
	}
	authz = instrumentedAuthorizer{next: authz, mode: *mode}

	reg := newServiceRegistry(*channelTTL)
	go reg.RunSweeper(ctx)

	proxy := NewProxy(backend, authz, reg, *apiPrefix, *reqBoth, *identityPfx)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var metricsSrv *http.Server
	if *metricsListen != "" {
		metricsSrv = &http.Server{
			Addr:              *metricsListen,
			Handler:           metricsHandler(metricsRegistry()),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics listener: %v", err)
			}
		}()
	}

	log.Printf("hubble-authz-proxy %s: listen=%s metrics=%s backend=%s authz=%s requireBoth=%v identityHeaders=%s-*",
		version, *listen, *metricsListen, backend, *mode, *reqBoth, *identityPfx)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	case <-ctx.Done():
		log.Printf("signal received, draining for up to %s", *shutdownGrace)
	}

	// Detached from ctx, which is already cancelled by the signal.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownGrace)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("proxy shutdown: %v", err)
	}
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("metrics shutdown: %v", err)
		}
	}
	log.Print("stopped")
}
