package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	uipb "github.com/cilium/hubble-ui/backend/proto/ui"
	"github.com/puzzle/hubble-authz-proxy/internal/authz"
	"github.com/puzzle/hubble-authz-proxy/internal/identity"
	"github.com/puzzle/hubble-authz-proxy/internal/registry"
	"google.golang.org/protobuf/proto"
)

func testProxy(requireBoth bool) *Proxy {
	return &Proxy{
		services:    registry.New(time.Minute, registry.DefaultMaxChannels),
		requireBoth: requireBoth,
		// Matches the shipped default, so these tests exercise the real
		// configuration rather than a quieter one.
		notifyEmptyScope: true,
		log:              testLogger(),
	}
}

func scopeOf(ns ...string) authz.Scope {
	m := map[string]bool{}
	for _, n := range ns {
		m[n] = true
	}
	return authz.Scope{Namespaces: m}
}

func svcEvent(id, ns string) *uipb.Event {
	return &uipb.Event{Event: &uipb.Event_ServiceState{
		ServiceState: &uipb.ServiceState{Service: &uipb.Service{Id: id, Namespace: ns}},
	}}
}

func linkEvent(id, srcID, dstID string) *uipb.Event {
	return &uipb.Event{Event: &uipb.Event_ServiceLinkState{
		ServiceLinkState: &uipb.ServiceLinkState{
			ServiceLink: &uipb.ServiceLink{Id: id, SourceId: srcID, DestinationId: dstID},
		},
	}}
}

func flowEvent(src, dst string) *uipb.Event {
	return &uipb.Event{Event: &uipb.Event_Flow{Flow: flowNS(src, dst)}}
}

// filterEvents runs a batch through the real marshal/filter/unmarshal path and
// returns what survived.
func filterEvents(t *testing.T, p *Proxy, channelID string, scope authz.Scope, events ...*uipb.Event) []*uipb.Event {
	t.Helper()
	body, err := proto.Marshal(&uipb.GetEventsResponse{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.filterBody(routeServiceMapStre, channelID, body, scope, identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	got := &uipb.GetEventsResponse{}
	if err := proto.Unmarshal(out, got); err != nil {
		t.Fatal(err)
	}
	return got.GetEvents()
}

func TestFilterServiceMapFlowsAndServices(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("payments")

	got := filterEvents(t, p, "ch1", scope,
		flowEvent("payments", "search"), // allowed <-> foreign: visible by default
		flowEvent("search", "other"),    // wholly foreign: dropped
		svcEvent("svc-pay", "payments"), // allowed
		svcEvent("svc-sea", "search"),   // foreign
	)

	if len(got) != 2 {
		t.Fatalf("kept %d events, want 2: %v", len(got), got)
	}
	if got[0].GetFlow().GetDestination().GetNamespace() != "search" {
		t.Errorf("expected the payments->search flow first, got %v", got[0])
	}
	if ns := got[1].GetServiceState().GetService().GetNamespace(); ns != "payments" {
		t.Errorf("expected the payments service, got namespace %q", ns)
	}
}

// The backend appends link events BEFORE the service events that name their
// endpoints, so filtering must learn every service in the batch first. A
// single-pass implementation would drop every link in the first response.
func TestFilterServiceLinkOrdering(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("payments")

	got := filterEvents(t, p, "ch1", scope,
		linkEvent("l1", "svc-pay", "svc-sea"), // link arrives first...
		svcEvent("svc-pay", "payments"),       // ...services after
		svcEvent("svc-sea", "search"),
	)

	var links int
	for _, ev := range got {
		if ev.GetServiceLinkState() != nil {
			links++
		}
	}
	if links != 1 {
		t.Fatalf("kept %d links, want 1 — services declared after the link were not learned first", links)
	}
}

// A link whose endpoints were never announced could point anywhere, so it must
// be dropped rather than assumed harmless.
func TestFilterServiceLinkUnknownEndpointFailsClosed(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("payments")

	got := filterEvents(t, p, "ch1", scope,
		svcEvent("svc-pay", "payments"),
		linkEvent("l1", "svc-pay", "svc-never-announced"),
	)

	for _, ev := range got {
		if ev.GetServiceLinkState() != nil {
			t.Error("a link with an unresolvable endpoint was forwarded")
		}
	}
}

func TestFilterServiceLinkRequireBoth(t *testing.T) {
	scope := scopeOf("payments")
	events := []*uipb.Event{
		svcEvent("svc-pay", "payments"),
		svcEvent("svc-sea", "search"),
		linkEvent("l1", "svc-pay", "svc-sea"),
	}

	countLinks := func(evs []*uipb.Event) int {
		n := 0
		for _, ev := range evs {
			if ev.GetServiceLinkState() != nil {
				n++
			}
		}
		return n
	}

	if n := countLinks(filterEvents(t, testProxy(false), "ch1", scope, events...)); n != 1 {
		t.Errorf("lenient: kept %d cross-namespace links, want 1", n)
	}
	if n := countLinks(filterEvents(t, testProxy(true), "ch2", scope, events...)); n != 0 {
		t.Errorf("strict: kept %d cross-namespace links, want 0", n)
	}
}

// Per-channel state must not let one caller's service map inform another's.
func TestServiceRegistryIsolatesChannels(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("payments")

	filterEvents(t, p, "ch1", scope, svcEvent("svc-pay", "payments"), svcEvent("svc-sea", "search"))

	// A different channel has learned nothing, so the same link is unresolvable.
	got := filterEvents(t, p, "ch2", scope, linkEvent("l1", "svc-pay", "svc-sea"))
	for _, ev := range got {
		if ev.GetServiceLinkState() != nil {
			t.Error("channel ch2 resolved a service it never saw announced")
		}
	}
}

func TestFilterBatchedFlows(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("payments")

	batch := &uipb.Event{Event: &uipb.Event_Flows{Flows: &uipb.Flows{Flows: []*flowpb.Flow{
		flowNS("payments", "payments"),
		flowNS("search", "other"),
		flowNS("other", "elsewhere"),
	}}}}

	got := filterEvents(t, p, "ch1", scope, batch)
	if len(got) != 1 {
		t.Fatalf("kept %d events, want 1", len(got))
	}
	if n := len(got[0].GetFlows().GetFlows()); n != 1 {
		t.Errorf("kept %d flows inside the batch, want 1", n)
	}

	// A batch with nothing visible must be dropped, not forwarded empty.
	empty := &uipb.Event{Event: &uipb.Event_Flows{Flows: &uipb.Flows{Flows: []*flowpb.Flow{
		flowNS("search", "other"),
	}}}}
	if got := filterEvents(t, p, "ch1", scope, empty); len(got) != 0 {
		t.Errorf("forwarded an empty flow batch: %v", got)
	}
}

func TestFilterControlStreamNamespaces(t *testing.T) {
	p := testProxy(false)
	body, err := proto.Marshal(&uipb.GetControlStreamResponse{
		Event: &uipb.GetControlStreamResponse_Namespaces{
			Namespaces: &uipb.GetControlStreamResponse_NamespaceStates{
				Namespaces: []*uipb.NamespaceState{
					{Namespace: &uipb.NamespaceDescriptor{Name: "payments"}},
					{Namespace: &uipb.NamespaceDescriptor{Name: "search"}},
					{Namespace: &uipb.NamespaceDescriptor{Name: "kube-system"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.filterBody(routeControlStream, "ch1", body, scopeOf("payments"), identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	got := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(out, got); err != nil {
		t.Fatal(err)
	}

	names := got.GetNamespaces().GetNamespaces()
	if len(names) != 1 || names[0].GetNamespace().GetName() != "payments" {
		t.Errorf("namespace picker leaked: %v", names)
	}
}

// Notifications are cluster-wide status, not namespace data, and the UI needs
// them to report relay connectivity.
func TestFilterControlStreamPassesNotifications(t *testing.T) {
	p := testProxy(false)
	body, err := proto.Marshal(&uipb.GetControlStreamResponse{
		Event: &uipb.GetControlStreamResponse_Notification{
			Notification: &uipb.Notification{
				Notification: &uipb.Notification_ConnState{
					ConnState: &uipb.ConnectionState{RelayConnected: true},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.filterBody(routeControlStream, "ch1", body, scopeOf("payments"), identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	got := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(out, got); err != nil {
		t.Fatal(err)
	}
	if !got.GetNotification().GetConnState().GetRelayConnected() {
		t.Error("dropped the relay connection-state notification")
	}
}

// --- empty-scope notification ---------------------------------------------

// namespacesBody is a control-stream response announcing namespaces the caller
// may or may not be allowed to see.
func namespacesBody(t *testing.T, names ...string) []byte {
	t.Helper()
	states := make([]*uipb.NamespaceState, 0, len(names))
	for _, n := range names {
		states = append(states, &uipb.NamespaceState{
			Namespace: &uipb.NamespaceDescriptor{Name: n},
		})
	}
	body, err := proto.Marshal(&uipb.GetControlStreamResponse{
		Event: &uipb.GetControlStreamResponse_Namespaces{
			Namespaces: &uipb.GetControlStreamResponse_NamespaceStates{Namespaces: states},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func decodeControl(t *testing.T, b []byte) *uipb.GetControlStreamResponse {
	t.Helper()
	got := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatal(err)
	}
	return got
}

// A caller granted nothing otherwise gets an empty picker and no explanation,
// which is indistinguishable from Hubble being broken.
func TestEmptyScopeGetsNoPermissionNotice(t *testing.T) {
	p := testProxy(false)
	id := identity.Identity{Email: "bob@example.com", Groups: []string{"devs"}}

	out, err := p.filterBody(routeControlStream, "ch1",
		namespacesBody(t, "payments", "search"), authz.Scope{}, id)
	if err != nil {
		t.Fatal(err)
	}

	np := decodeControl(t, out).GetNotification().GetNoPermission()
	if np == nil {
		t.Fatal("no NoPermission notification; the user is left with a blank UI and no reason")
	}
	// resource is interpolated into the UI's own fixed sentence, and error is
	// rendered as the entry's details.
	if np.GetResource() != "namespaces" {
		t.Errorf("resource = %q; it has to complete hubble-ui's wording", np.GetResource())
	}
	if !strings.Contains(np.GetError(), "bob@example.com") {
		t.Errorf("details do not name the identity: %q", np.GetError())
	}
	if !strings.Contains(np.GetError(), "devs") {
		t.Errorf("details do not name the groups an admin would map: %q", np.GetError())
	}
}

// The Status Center does not deduplicate — the backend dedupes its own notices —
// so repeating this per poll would bury the UI in identical warnings.
func TestEmptyScopeNoticeIsSentOncePerChannel(t *testing.T) {
	p := testProxy(false)

	first, err := p.filterBody(routeControlStream, "ch1", namespacesBody(t, "payments"), authz.Scope{}, identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if decodeControl(t, first).GetNotification().GetNoPermission() == nil {
		t.Fatal("first poll did not carry the notice")
	}

	for i := range 3 {
		again, err := p.filterBody(routeControlStream, "ch1", namespacesBody(t, "payments"), authz.Scope{}, identity.Identity{})
		if err != nil {
			t.Fatal(err)
		}
		got := decodeControl(t, again)
		if got.GetNotification().GetNoPermission() != nil {
			t.Fatalf("poll %d repeated the notice", i+2)
		}
		// And it must still be a well-formed, empty namespace list.
		if n := got.GetNamespaces().GetNamespaces(); len(n) != 0 {
			t.Errorf("poll %d leaked namespaces: %v", i+2, n)
		}
	}

	// A different channel is a different session and must be told.
	other, err := p.filterBody(routeControlStream, "ch2", namespacesBody(t, "payments"), authz.Scope{}, identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if decodeControl(t, other).GetNotification().GetNoPermission() == nil {
		t.Error("a second session was never told why its UI is empty")
	}
}

// The notice must never stand in for a real answer. A caller with access sees
// their namespaces, even when this particular batch happens to match none.
func TestNonEmptyScopeNeverGetsTheNotice(t *testing.T) {
	p := testProxy(false)

	t.Run("batch matches", func(t *testing.T) {
		out, err := p.filterBody(routeControlStream, "ch1",
			namespacesBody(t, "payments", "search"), scopeOf("payments"), identity.Identity{})
		if err != nil {
			t.Fatal(err)
		}
		got := decodeControl(t, out)
		if got.GetNotification().GetNoPermission() != nil {
			t.Fatal("told a caller with access that they have none")
		}
		if n := got.GetNamespaces().GetNamespaces(); len(n) != 1 {
			t.Errorf("expected 1 namespace, got %v", n)
		}
	})

	// The load-bearing case: scope is non-empty but nothing in this batch is in
	// it. Firing here would cry wolf at users who do have access, e.g. whose
	// namespaces arrive in a later batch.
	t.Run("batch matches nothing", func(t *testing.T) {
		out, err := p.filterBody(routeControlStream, "ch9",
			namespacesBody(t, "kube-system"), scopeOf("payments"), identity.Identity{})
		if err != nil {
			t.Fatal(err)
		}
		got := decodeControl(t, out)
		if got.GetNotification().GetNoPermission() != nil {
			t.Error("fired on an unmatched batch rather than an empty scope")
		}
		if got.GetNamespaces() == nil {
			t.Error("dropped the (empty) namespace list entirely")
		}
	})
}

// Turning it off has to restore the previous behaviour exactly, since the flag
// exists as the escape hatch if a hubble-ui release stops rendering this.
func TestEmptyScopeNoticeCanBeDisabled(t *testing.T) {
	p := testProxy(false)
	p.notifyEmptyScope = false

	out, err := p.filterBody(routeControlStream, "ch1", namespacesBody(t, "payments"), authz.Scope{}, identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeControl(t, out)
	if got.GetNotification() != nil {
		t.Error("sent a notification with the feature disabled")
	}
	if n := got.GetNamespaces().GetNamespaces(); len(n) != 0 {
		t.Errorf("leaked namespaces: %v", n)
	}
}

// An empty group list is itself a likely cause of an empty scope, so the advice
// must not point at groups that were never presented.
func TestEmptyScopeNoticeAdaptsToMissingGroups(t *testing.T) {
	without := noPermissionResponse(identity.Identity{Email: "bob@example.com"}).
		GetNotification().GetNoPermission().GetError()
	if strings.Contains(without, "these groups") {
		t.Errorf("points at groups the caller never presented: %q", without)
	}

	with := noPermissionResponse(identity.Identity{Email: "bob@example.com", Groups: []string{"devs"}}).
		GetNotification().GetNoPermission().GetError()
	if !strings.Contains(with, "these groups") {
		t.Errorf("does not offer the groups an admin could map: %q", with)
	}
}

// Groups are caller-supplied and unbounded, and this string is rendered in a
// browser.
func TestEmptyScopeNoticeBoundsGroups(t *testing.T) {
	many := make([]string, 50)
	for i := range many {
		many[i] = fmt.Sprintf("group-%02d", i)
	}
	msg := noPermissionResponse(identity.Identity{Email: "bob@example.com", Groups: many}).
		GetNotification().GetNoPermission().GetError()

	if strings.Contains(msg, "group-40") {
		t.Error("group list is not bounded")
	}
	if !strings.Contains(msg, "…") {
		t.Error("truncation is not signalled, so the list reads as complete")
	}
}

// A route this proxy does not understand must be refused, not passed through:
// a hubble-ui upgrade that adds one should break loudly rather than leak.
func TestFilterUnknownRouteIsRefused(t *testing.T) {
	p := testProxy(false)
	if _, err := p.filterBody("some-new-route", "ch1", []byte{0x01}, scopeOf("payments"), identity.Identity{}); err == nil {
		t.Error("unknown route was allowed through")
	}
}

func TestFilterEmptyBodyPassesThrough(t *testing.T) {
	p := testProxy(false)
	// Poll responses with no data carry an empty body and must survive, or the
	// client's long-poll loop breaks.
	got, err := p.filterBody("some-new-route", "ch1", nil, scopeOf("payments"), identity.Identity{})
	if err != nil || got != nil {
		t.Errorf("empty body: got %v, %v", got, err)
	}
}

// A service outside the caller's scope becomes visible once something inside
// their scope links to it. Without this the flow table names the peer (flows
// carry the full endpoint) while the service map has no node to draw it, so the
// edge dangles — which is what a real deployment surfaced.
func TestFilterPeerServiceBecomesVisible(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("mealie")

	got := filterEvents(t, p, "ch1", scope,
		svcEvent("svc-mealie", "mealie"),
		svcEvent("svc-traefik", "traefik"),           // foreign...
		linkEvent("l1", "svc-traefik", "svc-mealie"), // ...but talks to us
	)

	var seen []string
	for _, ev := range got {
		if s := ev.GetServiceState().GetService(); s != nil {
			seen = append(seen, s.GetNamespace())
		}
	}
	if len(seen) != 2 {
		t.Fatalf("services kept = %v, want both mealie and its traefik peer", seen)
	}
}

// Only the service actually linked becomes visible, not everything sharing its
// namespace: a busy ingress namespace should not be exposed wholesale.
func TestFilterPeerVisibilityIsPerService(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("mealie")

	got := filterEvents(t, p, "ch1", scope,
		svcEvent("svc-mealie", "mealie"),
		svcEvent("svc-traefik", "traefik"),
		svcEvent("svc-traefik-other", "traefik"), // same namespace, no link to us
		linkEvent("l1", "svc-traefik", "svc-mealie"),
	)

	for _, ev := range got {
		if s := ev.GetServiceState().GetService(); s != nil && s.GetId() == "svc-traefik-other" {
			t.Error("an unrelated service in the peer's namespace was exposed")
		}
	}
}

// Two services both outside scope, linked to each other, stay invisible.
func TestFilterPeerRequiresAnEndpointInScope(t *testing.T) {
	p := testProxy(false)
	scope := scopeOf("mealie")

	got := filterEvents(t, p, "ch1", scope,
		svcEvent("svc-a", "other-a"),
		svcEvent("svc-b", "other-b"),
		linkEvent("l1", "svc-a", "svc-b"),
	)

	for _, ev := range got {
		if s := ev.GetServiceState().GetService(); s != nil {
			t.Errorf("foreign service %q in %q leaked via a foreign-to-foreign link",
				s.GetId(), s.GetNamespace())
		}
	}
}

// Strict mode must not gain peers: hiding foreign namespaces entirely is the
// point of --require-both-endpoints.
func TestFilterStrictModeHasNoPeers(t *testing.T) {
	p := testProxy(true)
	scope := scopeOf("mealie")

	got := filterEvents(t, p, "ch1", scope,
		svcEvent("svc-mealie", "mealie"),
		svcEvent("svc-traefik", "traefik"),
		linkEvent("l1", "svc-traefik", "svc-mealie"),
	)

	for _, ev := range got {
		if s := ev.GetServiceState().GetService(); s != nil && s.GetNamespace() == "traefik" {
			t.Error("strict mode exposed a peer service")
		}
	}
}
