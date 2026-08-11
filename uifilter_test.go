package main

import (
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	uipb "github.com/cilium/hubble-ui/backend/proto/ui"
	"google.golang.org/protobuf/proto"
)

func testProxy(requireBoth bool) *Proxy {
	return &Proxy{
		services:    newServiceRegistry(time.Minute),
		requireBoth: requireBoth,
	}
}

func scopeOf(ns ...string) Scope {
	m := map[string]bool{}
	for _, n := range ns {
		m[n] = true
	}
	return Scope{Namespaces: m}
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
func filterEvents(t *testing.T, p *Proxy, channelID string, scope Scope, events ...*uipb.Event) []*uipb.Event {
	t.Helper()
	body, err := proto.Marshal(&uipb.GetEventsResponse{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.filterBody(routeServiceMapStre, channelID, body, scope)
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

	out, err := p.filterBody(routeControlStream, "ch1", body, scopeOf("payments"))
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

	out, err := p.filterBody(routeControlStream, "ch1", body, scopeOf("payments"))
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

// A route this proxy does not understand must be refused, not passed through:
// a hubble-ui upgrade that adds one should break loudly rather than leak.
func TestFilterUnknownRouteIsRefused(t *testing.T) {
	p := testProxy(false)
	if _, err := p.filterBody("some-new-route", "ch1", []byte{0x01}, scopeOf("payments")); err == nil {
		t.Error("unknown route was allowed through")
	}
}

func TestFilterEmptyBodyPassesThrough(t *testing.T) {
	p := testProxy(false)
	// Poll responses with no data carry an empty body and must survive, or the
	// client's long-poll loop breaks.
	got, err := p.filterBody("some-new-route", "ch1", nil, scopeOf("payments"))
	if err != nil || got != nil {
		t.Errorf("empty body: got %v, %v", got, err)
	}
}
