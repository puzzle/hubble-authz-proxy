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

import "os"

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
