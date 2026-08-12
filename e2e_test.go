//go:build e2e

// End-to-end tests against the real hubble-ui backend.
//
// These run the actual backend container in its E2E mode, which swaps its whole
// clients layer for one fed by log files — no relay and no Kubernetes needed.
// The flows in those files are ours, so the service map the backend builds is
// under our control, and we can assert what a scoped caller is allowed to see.
//
// This is the only test that exercises our filter against the backend's real
// aggregation. Everything else builds its input with the same code under test,
// so a wrong assumption about the wire format or about how ServiceLink endpoints
// are identified would be invisible.
//
//	go test -tags e2e -run TestE2E ./...
//
// Requires Docker. Skips if it is unavailable.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	cppb "github.com/cilium/hubble-ui/backend/proto/customprotocol"
	uipb "github.com/cilium/hubble-ui/backend/proto/ui"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Matches the hubble-ui-backend shipped by Cilium v1.19.1. Keep in step with the
// go.mod pin: the point of these tests is to catch that pairing drifting.
const backendImage = "quay.io/cilium/hubble-ui-backend:v0.13.3"

// The backend picks its scenario from a preset name, and tenant-jobs is the one
// that reads flows from log files. The namespace list it reports is hardcoded in
// the backend, but the flows — and therefore the whole service map — are ours.
const preset = "tenant-jobs"

const (
	nsA = "tenant-jobs"  // in scope for the test user
	nsB = "other-tenant" // never in scope
)

// endpoint builds a Cilium endpoint complete enough for the backend to derive a
// service from it: service identity comes from labels, not from the namespace.
func endpoint(ns, app string, identity uint32) *flowpb.Endpoint {
	return &flowpb.Endpoint{
		ID:        identity,
		Identity:  identity,
		Namespace: ns,
		PodName:   app + "-0",
		Labels: []string{
			"k8s:app=" + app,
			"k8s:io.kubernetes.pod.namespace=" + ns,
		},
		Workloads: []*flowpb.Workload{{Name: app, Kind: "Deployment"}},
	}
}

func flowBetween(src, dst *flowpb.Endpoint) *observerpb.GetFlowsResponse {
	return &observerpb.GetFlowsResponse{
		ResponseTypes: &observerpb.GetFlowsResponse_Flow{
			Flow: &flowpb.Flow{
				Time:             timestamppb.Now(),
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				Source:           src,
				Destination:      dst,
				NodeName:         "e2e-node",
				L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{SourcePort: 34567, DestinationPort: 8080},
				}},
			},
		},
	}
}

// writeFixtures lays out <dir>/<preset>/{hubble-events,fgs-events}.json.log.
// Each line is a protojson observer.GetFlowsResponse — the backend parses them
// with protojson.Unmarshal, so this is the same encoding it expects from a real
// capture. Both files must exist even when one is empty.
func writeFixtures(t *testing.T, dir string) {
	t.Helper()

	a1 := endpoint(nsA, "frontend", 1001)
	a2 := endpoint(nsA, "backend", 1002)
	b1 := endpoint(nsB, "peer-svc", 2001)     // foreign, but talks to us
	b2 := endpoint(nsB, "isolated-svc", 2002) // foreign, never talks to us

	flows := []*observerpb.GetFlowsResponse{
		flowBetween(a1, a2), // wholly in scope
		flowBetween(a1, b1), // in scope -> out of scope: the requireBoth case
		flowBetween(b2, b1), // wholly out of scope: must never be visible
	}
	// Repeat so the backend has enough to aggregate into stable services/links.
	var sb strings.Builder
	for range 20 {
		for _, f := range flows {
			line, err := protojson.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			sb.Write(line)
			sb.WriteString("\n")
		}
	}

	presetDir := filepath.Join(dir, preset)
	if err := os.MkdirAll(presetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// World-readable: the container runs as a different uid than the test.
	if err := os.WriteFile(filepath.Join(presetDir, "hubble-events.json.log"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(presetDir, "fgs-events.json.log"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// startBackend runs the real backend container and returns its base URL.
func startBackend(t *testing.T, fixtureDir string) string {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm",
		"-p", "127.0.0.1:0:8090",
		"-e", "E2E_TEST_MODE=true",
		"-e", "E2E_LOGFILES_BASEPATH=/e2e",
		"-e", "EVENTS_SERVER_PORT=8090",
		"-v", fixtureDir+":/e2e:ro",
		backendImage,
	).CombinedOutput()
	if err != nil {
		t.Skipf("cannot start %s: %v\n%s", backendImage, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "40", id).CombinedOutput()
			t.Logf("backend logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})

	portOut, err := exec.Command("docker", "port", id, "8090/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	hostPort := strings.TrimSpace(strings.Split(string(portOut), "\n")[0])
	base := "http://" + hostPort

	// The probe must carry a body: the backend routes on meta.route_name, not on
	// the URL, so a bodyless POST is answered 404 no matter how healthy it is.
	probe, err := json.Marshal(&cppb.Message{
		Meta: &cppb.Meta{RouteName: "control-stream"},
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := postRaw(base+"/api/control-stream", probe,
			map[string]string{"Content-Type": "application/json"}); err == nil {
			return base
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("backend at %s never became ready", base)
	return ""
}

// startProxy runs our proxy in-process against the backend.
func startProxy(t *testing.T, backendURL string, authz Authorizer, requireBoth bool) *httptest.Server {
	t.Helper()
	u, err := url.Parse(backendURL)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewProxy(u, authz, newServiceRegistry(time.Minute), "/api", requireBoth, AuthRequestPrefix, testMaxResponse, testLogger()))
	t.Cleanup(srv.Close)
	return srv
}

// collected is what a client saw across a whole polling session.
type collected struct {
	namespaces  map[string]bool
	serviceNS   map[string]bool
	serviceName map[string]bool
	linkNS      map[string]bool // "src->dst" namespace pairs, resolved by us
	serviceByID map[string]string
	flowNS      map[string]bool
	// flowPairs records "srcNS->dstNS" per visible flow. Tracking namespaces
	// individually cannot distinguish "only the cross-namespace flow survived"
	// from "the wholly foreign flow leaked" — both put nsB in the set.
	flowPairs map[string]bool
	statuses  int
}

// drive opens a service-map channel as the given identity and polls it, folding
// everything the caller was allowed to see into one summary.
func drive(t *testing.T, proxyURL string, headers map[string]string, polls int) *collected {
	t.Helper()

	got := &collected{
		namespaces: map[string]bool{}, serviceNS: map[string]bool{},
		serviceName: map[string]bool{},
		linkNS:      map[string]bool{}, serviceByID: map[string]string{},
		flowNS: map[string]bool{}, flowPairs: map[string]bool{},
	}

	req := &uipb.GetEventsRequest{EventTypes: []uipb.EventType{
		uipb.EventType_FLOW, uipb.EventType_FLOWS,
		uipb.EventType_SERVICE_STATE, uipb.EventType_SERVICE_LINK_STATE,
		uipb.EventType_K8S_NAMESPACE_STATE, uipb.EventType_STATUS,
	}}
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	// The preset is applied from a query param on the first request; sending it
	// again would reset the backend's mock state mid-session.
	first := &cppb.Message{
		Meta: &cppb.Meta{RouteName: "service-map-stream"},
		Body: &cppb.Body{Content: body},
	}
	channel := ""
	for i := range polls {
		msg := first
		path := "/api/service-map-stream?e2e=" + url.QueryEscape("preset="+preset)
		if channel != "" {
			msg = &cppb.Message{Meta: &cppb.Meta{
				RouteName: "service-map-stream", ChannelId: channel,
			}}
			path = "/api/service-map-stream"
		}
		payload, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}

		respBody, err := postRaw(proxyURL+path, payload,
			map[string]string{"Content-Type": "application/json"}, headers)
		if err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}

		env := &cppb.Message{}
		if err := json.Unmarshal(respBody, env); err != nil {
			t.Fatalf("poll %d: decode envelope: %v (%s)", i, err, truncate(respBody))
		}
		if channel == "" {
			channel = env.GetMeta().GetChannelId()
		}
		if len(env.GetBody().GetContent()) == 0 {
			time.Sleep(150 * time.Millisecond)
			continue
		}

		resp := &uipb.GetEventsResponse{}
		if err := proto.Unmarshal(env.GetBody().GetContent(), resp); err != nil {
			t.Fatalf("poll %d: decode payload: %v", i, err)
		}
		absorb(got, resp)
		time.Sleep(100 * time.Millisecond)
	}
	return got
}

func absorb(got *collected, resp *uipb.GetEventsResponse) {
	// Learn service namespaces first so links in the same batch resolve.
	for _, ev := range resp.GetEvents() {
		if svc := ev.GetServiceState().GetService(); svc != nil {
			got.serviceByID[svc.GetId()] = svc.GetNamespace()
		}
	}
	for _, ev := range resp.GetEvents() {
		switch {
		case ev.GetFlow() != nil:
			absorbFlow(got, ev.GetFlow())
		case ev.GetFlows() != nil:
			for _, f := range ev.GetFlows().GetFlows() {
				absorbFlow(got, f)
			}
		case ev.GetNamespaceState() != nil:
			got.namespaces[ev.GetNamespaceState().GetNamespace().GetName()] = true
		case ev.GetServiceState() != nil:
			svc := ev.GetServiceState().GetService()
			got.serviceNS[svc.GetNamespace()] = true
			got.serviceName[svc.GetName()] = true
		case ev.GetServiceLinkState() != nil:
			l := ev.GetServiceLinkState().GetServiceLink()
			got.linkNS[got.serviceByID[l.GetSourceId()]+"->"+got.serviceByID[l.GetDestinationId()]] = true
		case ev.GetNotification() != nil:
			got.statuses++
		}
	}
}

// postRaw issues a POST and returns the body, turning a non-2xx into an error
// whose message carries the status so tests can assert on it.
func postRaw(rawURL string, body []byte, headerMaps ...map[string]string) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, rdr)
	if err != nil {
		return nil, err
	}
	for _, hm := range headerMaps {
		for k, v := range hm {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return b, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(b))
	}
	return b, nil
}

func absorbFlow(got *collected, f *flowpb.Flow) {
	src := f.GetSource().GetNamespace()
	dst := f.GetDestination().GetNamespace()
	got.flowNS[src] = true
	got.flowNS[dst] = true
	got.flowPairs[src+"->"+dst] = true
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

// --- the tests ------------------------------------------------------------

func TestE2EServiceMapIsScoped(t *testing.T) {
	dir := t.TempDir()
	writeFixtures(t, dir)
	backend := startBackend(t, dir)

	authz := fakeAuthorizer{scope: scopeOf(nsA)}
	proxy := startProxy(t, backend, authz, false)

	got := drive(t, proxy.URL, map[string]string{
		"X-Auth-Request-Email":  "bob@example.com",
		"X-Auth-Request-Groups": "team-a",
	}, 40)

	t.Logf("serviceNS=%v names=%v links=%v flowPairs=%v statuses=%d",
		keys(got.serviceNS), keys(got.serviceName), keys(got.linkNS),
		keys(got.flowPairs), got.statuses)

	if len(got.flowPairs) == 0 && len(got.serviceNS) == 0 {
		t.Fatal("saw nothing at all; the fixture or preset wiring is wrong")
	}

	// The load-bearing negative: traffic with neither end in scope must never
	// appear, however much of it the backend aggregated.
	if got.flowPairs[nsB+"->"+nsB] {
		t.Errorf("a wholly out-of-scope flow (%s->%s) reached the caller", nsB, nsB)
	}
	if got.linkNS[nsB+"->"+nsB] {
		t.Errorf("a wholly out-of-scope link (%s->%s) was visible", nsB, nsB)
	}

	// The peer rule: a foreign service linked to our scope IS shown, so the map
	// can draw the edge the flow table already names...
	if !got.serviceName["peer-svc"] {
		t.Error("the foreign service linked to our scope was not shown; " +
			"its edge would dangle at nothing")
	}
	// ...but only that one. A foreign service that never talks to us must stay
	// hidden, or the rule degenerates into exposing whole namespaces.
	if got.serviceName["isolated-svc"] {
		t.Error("a foreign service with no link into our scope was exposed")
	}
	// And the edge must now resolve at both ends, which is the whole point.
	if !got.linkNS[nsA+"->"+nsB] {
		t.Errorf("the cross-namespace link did not resolve: %v", keys(got.linkNS))
	}

	// And the lenient policy's defining behaviour: traffic with one end in scope
	// IS shown, which is what reveals the peer namespace name.
	if !got.flowPairs[nsA+"->"+nsB] {
		t.Errorf("lenient mode hid the %s->%s flow; expected it to be visible", nsA, nsB)
	}
}

func TestE2ERequireBothEndpointsDropsCrossNamespace(t *testing.T) {
	dir := t.TempDir()
	writeFixtures(t, dir)
	backend := startBackend(t, dir)

	authz := fakeAuthorizer{scope: scopeOf(nsA)}
	proxy := startProxy(t, backend, authz, true) // strict

	got := drive(t, proxy.URL, map[string]string{
		"X-Auth-Request-Email": "bob@example.com",
	}, 40)

	t.Logf("strict: serviceNS=%v names=%v links=%v flowPairs=%v",
		keys(got.serviceNS), keys(got.serviceName), keys(got.linkNS), keys(got.flowPairs))

	if got.flowPairs[nsA+"->"+nsB] || got.flowPairs[nsB+"->"+nsA] {
		t.Errorf("strict mode kept a cross-namespace flow: %v", keys(got.flowPairs))
	}
	if got.flowPairs[nsB+"->"+nsB] {
		t.Errorf("strict mode leaked a wholly foreign flow")
	}
	if got.serviceNS[nsB] {
		t.Errorf("strict mode leaked a service in %q; peers are lenient-only", nsB)
	}
}

func TestE2EAdminSeesEverything(t *testing.T) {
	dir := t.TempDir()
	writeFixtures(t, dir)
	backend := startBackend(t, dir)

	proxy := startProxy(t, backend, fakeAuthorizer{scope: Scope{All: true}}, false)

	got := drive(t, proxy.URL, map[string]string{
		"X-Auth-Request-Email": "alice@example.com",
	}, 40)

	t.Logf("admin: services=%v flowPairs=%v", keys(got.serviceNS), keys(got.flowPairs))
	if !got.serviceName["isolated-svc"] && !got.serviceNS[nsB] {
		t.Errorf("admin saw nothing from %q; filtering was applied to an unrestricted caller", nsB)
	}
}

func TestE2ERejectsMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	writeFixtures(t, dir)
	backend := startBackend(t, dir)
	proxy := startProxy(t, backend, fakeAuthorizer{scope: scopeOf(nsA)}, false)

	payload, err := json.Marshal(&cppb.Message{
		Meta: &cppb.Meta{RouteName: "control-stream"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = postRaw(proxy.URL+"/api/control-stream", payload,
		map[string]string{"Content-Type": "application/json"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("want a 401 without identity headers, got %v", err)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
