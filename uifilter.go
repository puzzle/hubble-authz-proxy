package main

import (
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	uipb "github.com/cilium/hubble-ui/backend/proto/ui"
	"google.golang.org/protobuf/proto"
)

// Route names served by the hubble-ui backend. Anything else is refused rather
// than forwarded — see filterBody.
const (
	routeControlStream  = "control-stream"
	routeServiceMapStre = "service-map-stream"
)

var errUnknownRoute = fmt.Errorf("unknown backend route")

// filterBody rewrites one customprotocol body for a scoped caller.
//
// route is the route name the BACKEND reported in its response envelope, not
// anything the client supplied, so a client cannot pick which filter runs by
// lying about the URL or the request meta.
func (p *Proxy) filterBody(route, channelID string, body []byte, scope Scope) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	switch route {
	case routeControlStream:
		return p.filterControlStream(body, scope)
	case routeServiceMapStre:
		return p.filterServiceMapStream(channelID, body, scope)
	default:
		// Fail closed. A route we do not understand may carry namespace data in
		// a shape we cannot inspect, so it must not reach a scoped caller. If a
		// hubble-ui upgrade adds a route, this is the signal to teach the proxy
		// about it.
		return nil, fmt.Errorf("%w: %q", errUnknownRoute, route)
	}
}

// filterControlStream drops namespaces the caller may not see from the UI's
// namespace picker. Notifications (relay/k8s connection state, server status)
// are cluster-wide and pass through.
func (p *Proxy) filterControlStream(body []byte, scope Scope) ([]byte, error) {
	resp := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(body, resp); err != nil {
		return nil, fmt.Errorf("unmarshal GetControlStreamResponse: %w", err)
	}

	states := resp.GetNamespaces()
	if states == nil {
		return body, nil
	}

	kept := make([]*uipb.NamespaceState, 0, len(states.GetNamespaces()))
	for _, ns := range states.GetNamespaces() {
		if scope.Namespaces[ns.GetNamespace().GetName()] {
			kept = append(kept, ns)
		}
	}
	states.Namespaces = kept

	return proto.Marshal(resp)
}

// filterServiceMapStream drops flows, services and service-map edges the caller
// may not see.
//
// KNOWN LIMITATION: the backend aggregates before we filter, so the counters on
// a service or link the caller IS allowed to see (flow_amount, bytes_transfered,
// latency) were computed over all flows, including ones outside their scope.
// Namespace names and topology do not leak, but those totals are a coarse
// inference channel. Removing it entirely would require filtering upstream of
// the aggregation, i.e. between the backend and relay.
func (p *Proxy) filterServiceMapStream(channelID string, body []byte, scope Scope) ([]byte, error) {
	resp := &uipb.GetEventsResponse{}
	if err := proto.Unmarshal(body, resp); err != nil {
		return nil, fmt.Errorf("unmarshal GetEventsResponse: %w", err)
	}

	// Pass 1: learn every service's namespace before deciding anything. The
	// backend appends link events BEFORE service events in the same response
	// (see api_helpers.EventResponseFromEverything), so a link can reference a
	// service announced later in this very batch. Record forbidden services too
	// — their namespace is what tells us to drop links touching them.
	for _, ev := range resp.GetEvents() {
		if svc := ev.GetServiceState().GetService(); svc != nil {
			p.services.remember(channelID, svc.GetId(), svc.GetNamespace())
		}
	}

	// Pass 2: keep what the caller may see.
	kept := make([]*uipb.Event, 0, len(resp.GetEvents()))
	for _, ev := range resp.GetEvents() {
		if e, ok := p.eventVisible(channelID, ev, scope); ok {
			kept = append(kept, e)
		}
	}
	resp.Events = kept

	return proto.Marshal(resp)
}

// eventVisible decides a single service-map event. The returned event may be a
// trimmed copy (for batched flows); ok=false means drop it entirely.
func (p *Proxy) eventVisible(channelID string, ev *uipb.Event, scope Scope) (*uipb.Event, bool) {
	allowed, both := scope.Namespaces, p.requireBoth

	switch e := ev.GetEvent().(type) {
	case *uipb.Event_Flow:
		return ev, flowVisible(e.Flow, allowed, both)

	case *uipb.Event_Flows:
		flows := e.Flows.GetFlows()
		keep := make([]*flowpb.Flow, 0, len(flows))
		for _, f := range flows {
			if flowVisible(f, allowed, both) {
				keep = append(keep, f)
			}
		}
		if len(keep) == 0 {
			return nil, false
		}
		e.Flows.Flows = keep
		return ev, true

	case *uipb.Event_NamespaceState:
		return ev, allowed[e.NamespaceState.GetNamespace().GetName()]

	case *uipb.Event_ServiceState:
		return ev, allowed[e.ServiceState.GetService().GetNamespace()]

	case *uipb.Event_ServiceLinkState:
		link := e.ServiceLinkState.GetServiceLink()
		srcNS, srcKnown := p.services.lookup(channelID, link.GetSourceId())
		dstNS, dstKnown := p.services.lookup(channelID, link.GetDestinationId())
		if !srcKnown || !dstKnown {
			// An endpoint we have never seen announced could be in any
			// namespace, so we cannot prove the caller may see this edge.
			return nil, false
		}
		return ev, namespacePairVisible(srcNS, dstNS, allowed, both)

	case *uipb.Event_Notification:
		// Connection/data state and server status are cluster-wide.
		return ev, true

	default:
		// Unrecognised event kind: fail closed, same reasoning as unknown routes.
		return nil, false
	}
}
