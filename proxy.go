package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Proxy is an HTTP reverse proxy that sits between the hubble-ui frontend
// (nginx, which proxies /api) and the unmodified hubble-ui backend:
//
//	browser -> oauth2-proxy -> frontend(nginx) -/api-> THIS PROXY -> hubble-ui-backend -> relay
//
// It is on the correct side of the identity boundary: the caller's oauth2-proxy
// headers are still present here, whereas the backend opens its own connection
// to relay under a machine identity and forwards nothing about the caller.
//
// Enforcement is entirely response-side. Requests are relayed untouched, so a
// user cannot widen their scope by crafting UI filters — whatever the backend
// sends back is filtered against their namespace set before it reaches them.
type Proxy struct {
	rp          *httputil.ReverseProxy
	authz       Authorizer
	services    *serviceRegistry
	requireBoth bool
	apiPrefix   string
	headers     identityHeaders
	log         *slog.Logger
}

type ctxKey int

const reqInfoCtxKey ctxKey = iota

// reqInfo is attached by ServeHTTP to every request it forwards.
//
// ModifyResponse runs for all proxied responses, including paths that carry no
// namespace data, so "must this be filtered?" is recorded explicitly rather than
// inferred from a missing scope. That way an absent reqInfo stays an error —
// a request that somehow reached the backend without passing through ServeHTTP
// must not have its response served.
type reqInfo struct {
	filtered bool
	scope    Scope
}

func NewProxy(backend *url.URL, authz Authorizer, reg *serviceRegistry, apiPrefix string, requireBoth bool, identityPrefix string, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	p := &Proxy{
		authz:       authz,
		services:    reg,
		requireBoth: requireBoth,
		apiPrefix:   apiPrefix,
		headers:     newIdentityHeaders(identityPrefix),
		log:         logger,
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backend)
			r.Out.Host = r.In.Host
			// We have to read the response body to filter it, so make sure the
			// backend does not hand us something compressed.
			r.Out.Header.Set("Accept-Encoding", "identity")
		},
		ModifyResponse: p.filterResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Reached both for upstream failures and for a filter that refused
			// to vouch for a response, so this must not leak the body.
			route := knownRoute(strings.TrimPrefix(r.URL.Path, apiPrefix))

			if clientGone(err) {
				// The caller left; there is nobody to send a status to. Counted
				// rather than dropped: the rate matters even though any single
				// occurrence is unremarkable. See clientGone.
				requestsTotal.WithLabelValues(route, outcomeClientGone).Inc()
				p.log.Debug("client disconnected before the response completed",
					"route", route, "path", r.URL.Path, "err", err)
				return
			}

			requestsTotal.WithLabelValues(route, outcomeUpstreamError).Inc()
			p.log.Error("refusing to serve response",
				"route", route, "path", r.URL.Path, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health checks and static assets are not namespace-bearing, and must not
	// require an identity.
	if !strings.HasPrefix(r.URL.Path, p.apiPrefix) {
		requestsTotal.WithLabelValues(routeNone, outcomePassthrough).Inc()
		ctx := context.WithValue(r.Context(), reqInfoCtxKey, reqInfo{filtered: false})
		p.rp.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// Label by the path segment rather than the backend's authoritative route
	// name, which is only known once the response comes back. Bounded by
	// knownRoute so a caller cannot blow up metric cardinality with random paths.
	route := knownRoute(strings.TrimPrefix(r.URL.Path, p.apiPrefix))
	timer := prometheus.NewTimer(requestDuration.WithLabelValues(route))
	defer timer.ObserveDuration()

	id, err := p.headers.from(r)
	if err != nil {
		requestsTotal.WithLabelValues(route, outcomeUnauthenticated).Inc()
		// Name the headers rather than the values, and say explicitly when the
		// other family is present: a prefix mismatch otherwise looks exactly
		// like an authenticator that is not running at all.
		p.log.Warn("no identity on request",
			"route", route,
			"expecting", p.headers.email+" (and -User/-Groups)",
			"present", p.headers.presentIn(r),
			"other_family_present", p.headers.otherFamilyIn(r))
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	scope, err := p.authz.AllowedNamespaces(r.Context(), id)
	if err != nil {
		requestsTotal.WithLabelValues(route, outcomeAuthzError).Inc()
		if clientGone(err) {
			p.log.Debug("caller left while their scope was being resolved",
				"route", route, "user", id.Email)
			return
		}
		p.log.Error("cannot resolve allowed namespaces",
			"user", id.Email, "groups", id.Groups, "err", err)
		http.Error(w, "authorization backend unavailable", http.StatusInternalServerError)
		return
	}

	// The single most useful line when someone reports seeing nothing: it shows
	// the identity that actually arrived and what it resolved to.
	p.log.Debug("request authorized",
		"route", route,
		"user", cmpOr(id.Email, id.User),
		"groups", id.Groups,
		"unrestricted", scope.All,
		"namespaces", len(scope.Namespaces))

	requestsTotal.WithLabelValues(route, outcomeFiltered).Inc()
	ctx := context.WithValue(r.Context(), reqInfoCtxKey, reqInfo{filtered: true, scope: scope})
	p.rp.ServeHTTP(w, r.WithContext(ctx))
}

// filterResponse rewrites the backend's customprotocol envelope in place.
//
// Returning an error here makes ReverseProxy discard the response and invoke
// ErrorHandler, so every failure path below is fail-closed: the caller gets a
// 502 rather than an unfiltered body.
func (p *Proxy) filterResponse(resp *http.Response) error {
	info, ok := resp.Request.Context().Value(reqInfoCtxKey).(reqInfo)
	if !ok {
		return errors.New("no reqInfo on request context")
	}
	if !info.filtered {
		return nil // not an API route: carries no namespace data
	}
	scope := info.scope
	if scope.All {
		return nil // cluster-admin: nothing to filter
	}
	if resp.StatusCode != http.StatusOK {
		return nil // errors carry no flow data
	}

	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.HasPrefix(contentType, "application/json")
	if !isJSON && !strings.HasPrefix(contentType, "application/octet-stream") {
		return errors.New("unexpected content-type from backend: " + contentType)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	msg, err := decodeEnvelope(raw, isJSON)
	if err != nil {
		return err
	}

	// The backend stamps the route it actually served, so this is not
	// client-controlled.
	route := msg.GetMeta().GetRouteName()
	channelID := msg.GetMeta().GetChannelId()

	filtered, err := p.filterBody(route, channelID, msg.GetBody().GetContent(), scope)
	if err != nil {
		return err
	}
	if msg.GetBody() != nil {
		msg.Body.Content = filtered
	}

	out, err := encodeEnvelope(msg, isJSON)
	if err != nil {
		return err
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}
