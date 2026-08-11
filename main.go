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
	"errors"
	"flag"
	"log"
	"net/http"
	"net/url"
	"time"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		listen     = flag.String("listen", ":8090", "address the Hubble UI frontend proxies /api to")
		backendURL = flag.String("backend", "http://hubble-ui-backend:8090", "upstream hubble-ui backend base URL")
		apiPrefix  = flag.String("api-prefix", "/api", "path prefix carrying backend routes; everything else is passed through")
		mode       = flag.String("authz", "static", "authorization backend: static | rbac")
		mapFile    = flag.String("authz-config", "/etc/hubble-authz/mapping.yaml", "static mode: group/user -> namespace mapping")
		rbacTTL    = flag.Duration("rbac-ttl", 60*time.Second, "rbac mode: cache TTL for a caller's resolved namespace set")
		channelTTL = flag.Duration("channel-ttl", 10*time.Minute, "how long to keep per-channel service-map state after a client goes idle")
		reqBoth    = flag.Bool("require-both-endpoints", false, "only show traffic when BOTH endpoints are in allowed namespaces (stricter)")
	)
	flag.Parse()

	backend, err := url.Parse(*backendURL)
	if err != nil {
		log.Fatalf("parse -backend: %v", err)
	}
	if backend.Scheme == "" || backend.Host == "" {
		log.Fatalf("-backend must be an absolute URL, got %q", *backendURL)
	}

	var authz Authorizer
	switch *mode {
	case "static":
		authz, err = NewStaticAuthorizer(*mapFile)
	case "rbac":
		authz, err = NewRBACAuthorizer(*rbacTTL)
	default:
		err = errors.New("unknown -authz mode (want static|rbac)")
	}
	if err != nil {
		log.Fatalf("authorizer: %v", err)
	}

	reg := newServiceRegistry(*channelTTL)
	stop := make(chan struct{})
	defer close(stop)
	go reg.runSweeper(stop)

	proxy := NewProxy(backend, authz, reg, *apiPrefix, *reqBoth)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("hubble-authz-proxy %s: listen=%s backend=%s authz=%s requireBoth=%v",
		version, *listen, backend, *mode, *reqBoth)
	log.Fatal(srv.ListenAndServe())
}
