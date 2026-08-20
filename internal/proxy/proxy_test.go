package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	cppb "github.com/cilium/hubble-ui/backend/proto/customprotocol"
	uipb "github.com/cilium/hubble-ui/backend/proto/ui"
	"github.com/puzzle/hubble-authz-proxy/internal/authz"
	"github.com/puzzle/hubble-authz-proxy/internal/identity"
	"github.com/puzzle/hubble-authz-proxy/internal/registry"
	"google.golang.org/protobuf/proto"
)

// fakeAuthorizer avoids needing a mapping file or a cluster.
type fakeAuthorizer struct {
	scope authz.Scope
	err   error
}

func (f fakeAuthorizer) AllowedNamespaces(context.Context, identity.Identity) (authz.Scope, error) {
	return f.scope, f.err
}

// newStack wires the proxy in front of a stub backend that answers every POST
// with the given envelope, encoded the way the real backend would.
func newStack(t *testing.T, authz authz.Authorizer, requireBoth bool, msg *cppb.Message, asJSON bool) *httptest.Server {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := encodeEnvelope(msg, asJSON)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if asJSON {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(backend.Close)

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(New(u, authz, registry.New(time.Minute, registry.DefaultMaxChannels), "/api", requireBoth, identity.AuthRequestPrefix, testMaxResponse, true, testLogger()))
	t.Cleanup(front.Close)
	return front
}

func post(t *testing.T, srv *httptest.Server, path string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func envelopeWith(route string, payload proto.Message) *cppb.Message {
	body, err := proto.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return &cppb.Message{
		Meta: &cppb.Meta{RouteName: route, ChannelId: "ch1"},
		Body: &cppb.Body{Content: body},
	}
}

func threeNamespaces() *uipb.GetControlStreamResponse {
	return &uipb.GetControlStreamResponse{
		Event: &uipb.GetControlStreamResponse_Namespaces{
			Namespaces: &uipb.GetControlStreamResponse_NamespaceStates{
				Namespaces: []*uipb.NamespaceState{
					{Namespace: &uipb.NamespaceDescriptor{Name: "payments"}},
					{Namespace: &uipb.NamespaceDescriptor{Name: "search"}},
					{Namespace: &uipb.NamespaceDescriptor{Name: "kube-system"}},
				},
			},
		},
	}
}

func decodeNamespaces(t *testing.T, resp *http.Response, asJSON bool) []string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := decodeEnvelope(raw, asJSON)
	if err != nil {
		t.Fatal(err)
	}
	out := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(msg.GetBody().GetContent(), out); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ns := range out.GetNamespaces().GetNamespaces() {
		names = append(names, ns.GetNamespace().GetName())
	}
	return names
}

func TestEndToEndFiltersNamespaces(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		name := "protobuf envelope"
		if asJSON {
			name = "json envelope"
		}
		t.Run(name, func(t *testing.T) {
			authz := fakeAuthorizer{scope: scopeOf("payments")}
			srv := newStack(t, authz, false,
				envelopeWith(routeControlStream, threeNamespaces()), asJSON)

			resp := post(t, srv, "/api/control-stream", map[string]string{
				"X-Auth-Request-Email": "bob@example.com",
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}

			names := decodeNamespaces(t, resp, asJSON)
			if len(names) != 1 || names[0] != "payments" {
				t.Errorf("got namespaces %v, want [payments]", names)
			}
		})
	}
}

// Content-Length must track the rewritten body, or the client hangs waiting for
// bytes that will never arrive.
func TestEndToEndRewritesContentLength(t *testing.T) {
	authz := fakeAuthorizer{scope: scopeOf("payments")}
	srv := newStack(t, authz, false,
		envelopeWith(routeControlStream, threeNamespaces()), false)

	resp := post(t, srv, "/api/control-stream", map[string]string{
		"X-Auth-Request-Email": "bob@example.com",
	})
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != int64(len(raw)) {
		t.Errorf("Content-Length %d, actual body %d", resp.ContentLength, len(raw))
	}
}

func TestEndToEndAdminBypassesFiltering(t *testing.T) {
	authz := fakeAuthorizer{scope: authz.Scope{All: true}}
	srv := newStack(t, authz, false,
		envelopeWith(routeControlStream, threeNamespaces()), false)

	resp := post(t, srv, "/api/control-stream", map[string]string{
		"X-Auth-Request-Email": "alice@example.com",
	})
	if names := decodeNamespaces(t, resp, false); len(names) != 3 {
		t.Errorf("admin got %v, want all three namespaces", names)
	}
}

func TestEndToEndRejectsMissingIdentity(t *testing.T) {
	authz := fakeAuthorizer{scope: scopeOf("payments")}
	srv := newStack(t, authz, false,
		envelopeWith(routeControlStream, threeNamespaces()), false)

	resp := post(t, srv, "/api/control-stream", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 — an unauthenticated caller must not reach the backend", resp.StatusCode)
	}
}

// If the backend serves a route the proxy cannot filter, the caller must get an
// error rather than the raw body.
func TestEndToEndUnknownRouteFailsClosed(t *testing.T) {
	authz := fakeAuthorizer{scope: scopeOf("payments")}
	srv := newStack(t, authz, false,
		envelopeWith("brand-new-route", threeNamespaces()), false)

	resp := post(t, srv, "/api/brand-new-route", map[string]string{
		"X-Auth-Request-Email": "bob@example.com",
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if bytes.Contains(raw, []byte("kube-system")) {
		t.Error("unfiltered backend body leaked through the error path")
	}
}

// The backend's long-poll handshake: the channel is open but has no data yet, so
// it answers with an empty body and asks the client to poll again. Observed
// verbatim from a real cluster:
//
//	{"meta":{"trace_id":"…","channel_id":"…","route_name":"control-stream",
//	         "is_not_ready":true,"poll_delay_ms":200,"is_empty":true},"body":{}}
//
// These must survive untouched. Filtering them into an error would stall the
// UI's poll loop, and the poll metadata is what tells the client to come back.
func TestEndToEndNotReadyPollPassesThrough(t *testing.T) {
	notReady := &cppb.Message{
		Meta: &cppb.Meta{
			TraceId:     "cfe1b42f578d7ef9",
			ChannelId:   "58a10da31d4e39f9",
			RouteName:   routeControlStream,
			IsNotReady:  true,
			IsEmpty:     true,
			PollDelayMs: 200,
		},
		Body: &cppb.Body{},
	}

	authz := fakeAuthorizer{scope: scopeOf("payments")}
	srv := newStack(t, authz, false, notReady, true)

	resp := post(t, srv, "/api/control-stream", map[string]string{
		"X-Auth-Request-Email": "bob@example.com",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeEnvelope(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.GetMeta().GetIsNotReady() || got.GetMeta().GetPollDelayMs() != 200 {
		t.Errorf("poll metadata lost: %+v", got.GetMeta())
	}
	if got.GetMeta().GetChannelId() != "58a10da31d4e39f9" {
		t.Errorf("channel id lost: %q", got.GetMeta().GetChannelId())
	}
}

// Paths outside the API prefix are not namespace-bearing and must pass through
// without requiring identity, so health checks keep working.
func TestNonAPIPathsPassThrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)

	front := httptest.NewServer(New(u, fakeAuthorizer{scope: scopeOf("payments")},
		registry.New(time.Minute, registry.DefaultMaxChannels), "/api", false, identity.AuthRequestPrefix, testMaxResponse, true, testLogger()))
	t.Cleanup(front.Close)

	resp := post(t, front, "/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
}

// The JSON envelope is produced by the backend with encoding/json over the
// generated struct, not protojson. If we ever switch to protojson the field
// names change and the frontend breaks, so pin the shape.
func TestJSONEnvelopeUsesStructTags(t *testing.T) {
	msg := envelopeWith(routeControlStream, threeNamespaces())
	raw, err := encodeEnvelope(msg, true)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	meta, ok := generic["meta"].(map[string]any)
	if !ok {
		t.Fatalf("no meta object in %s", raw)
	}
	if _, ok := meta["route_name"]; !ok {
		t.Errorf("meta keys = %v, want snake_case route_name", meta)
	}
}

// newStackLimited is newStack with a response-size cap, and a backend that
// answers with a body of the requested size.
func newStackLimited(t *testing.T, maxResponse int64, bodyBytes int) *httptest.Server {
	t.Helper()

	// A real envelope, padded to the target size so it is valid but oversized:
	// the point is that the limit trips before any of it is served, not that a
	// malformed body is rejected.
	ns := threeNamespaces()
	pad := make([]byte, bodyBytes)
	for i := range pad {
		pad[i] = 'a'
	}
	ns.GetNamespaces().Namespaces = append(ns.GetNamespaces().GetNamespaces(),
		&uipb.NamespaceState{Namespace: &uipb.NamespaceDescriptor{Name: "payments-" + string(pad)}})
	msg := envelopeWith(routeControlStream, ns)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := encodeEnvelope(msg, true)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(backend.Close)

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(New(u, fakeAuthorizer{scope: scopeOf("payments")},
		registry.New(time.Minute, registry.DefaultMaxChannels), "/api", false, identity.AuthRequestPrefix, maxResponse, true, testLogger()))
	t.Cleanup(front.Close)
	return front
}

// An oversized response must be refused outright. Filtering a truncated body
// would be worse than useless: the decode would fail, or worse, succeed on a
// prefix and produce a partially-filtered result.
func TestResponseOverLimitIsRefused(t *testing.T) {
	srv := newStackLimited(t, 1024, 64*1024)

	resp := post(t, srv, "/api/control-stream", map[string]string{
		"X-Auth-Request-Email": "bob@example.com",
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	// Nothing of the backend's payload may reach the caller, filtered or not.
	if bytes.Contains(raw, []byte("kube-system")) || bytes.Contains(raw, []byte("aaaa")) {
		t.Error("part of the oversized response leaked to the caller")
	}
}

// The limit must not disturb normal traffic, including a body sitting exactly
// at the boundary — the read goes one byte past it precisely so that "equal to
// the limit" is not mistaken for "truncated".
func TestResponseUnderLimitIsServed(t *testing.T) {
	srv := newStackLimited(t, 1<<20, 16)

	resp := post(t, srv, "/api/control-stream", map[string]string{
		"X-Auth-Request-Email": "bob@example.com",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if names := decodeNamespaces(t, resp, true); len(names) != 1 || names[0] != "payments" {
		t.Errorf("got %v, want the filtered [payments]", names)
	}
}
