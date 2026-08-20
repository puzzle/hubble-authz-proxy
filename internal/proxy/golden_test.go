package proxy

import (
	"os"
	"testing"

	uipb "github.com/cilium/hubble-ui/backend/proto/ui"
	"github.com/puzzle/hubble-authz-proxy/internal/identity"
	"google.golang.org/protobuf/proto"
)

// testdata/control-stream-status.json is a real control-stream response
// captured from a Cilium v1.19.1 cluster, with node names, addresses and TLS
// server names replaced by placeholders. Everything else — the envelope shape,
// the protojson-in-base64 body, the message structure — is verbatim.
//
// It guards the decode path against reality rather than against our own
// encoder: every other test builds its input with the same code under test, so
// a wrong assumption about the wire format would be invisible. This file would
// break if bumping the hubble-ui/backend pin changed the format.
const goldenStatusFile = "testdata/control-stream-status.json"

func loadGolden(t *testing.T, path string) ([]byte, string, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := decodeEnvelope(raw, true)
	if err != nil {
		t.Fatalf("real captured envelope no longer decodes: %v", err)
	}
	return msg.GetBody().GetContent(), msg.GetMeta().GetRouteName(), msg.GetMeta().GetChannelId()
}

func TestGoldenControlStreamDecodes(t *testing.T) {
	body, route, channel := loadGolden(t, goldenStatusFile)

	if route != routeControlStream {
		t.Errorf("route = %q, want %q", route, routeControlStream)
	}
	if channel == "" {
		t.Error("no channel id; the registry keys per-channel state on it")
	}
	if len(body) == 0 {
		t.Fatal("empty body")
	}

	resp := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(body, resp); err != nil {
		t.Fatalf("body is no longer a GetControlStreamResponse: %v", err)
	}
	if resp.GetNotification() == nil {
		t.Fatal("expected a notification event")
	}
}

// The first message a real client receives is node status, and a scoped caller
// gets all of it. This is deliberate — it is namespace-independent and the UI
// header needs it — but it is also the project's largest deliberate disclosure,
// so pin it against real bytes rather than leaving it implied.
//
// If this ever starts failing, someone changed the node-status policy; that is a
// decision to make consciously, not a test to fix.
func TestGoldenNodeStatusReachesScopedCaller(t *testing.T) {
	body, route, channel := loadGolden(t, goldenStatusFile)

	p := testProxy(false)
	// A caller scoped to a namespace that does not appear anywhere in the
	// payload: nothing here is theirs, yet the status still passes.
	out, err := p.filterBody(route, channel, body, scopeOf("some-unrelated-ns"), identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}

	resp := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(out, resp); err != nil {
		t.Fatal(err)
	}
	nodes := resp.GetNotification().GetStatus().GetNodes().GetNodes()
	if len(nodes) == 0 {
		t.Fatal("node status was dropped; the UI header depends on it")
	}
	for _, n := range nodes {
		if n.GetName() == "" || n.GetAddress() == "" {
			continue
		}
		t.Logf("node %s at %s is visible to a caller scoped elsewhere",
			n.GetName(), n.GetAddress())
		break
	}
	if st := resp.GetNotification().GetStatus().GetServerStatus(); st == nil {
		t.Error("relay server status was dropped")
	}
}

// A scoped caller must not receive namespaces outside their scope even when the
// payload is a real one. Uses the captured envelope's own route and channel so
// the filter runs exactly as it would in production.
func TestGoldenNamespacesAreFiltered(t *testing.T) {
	_, route, channel := loadGolden(t, goldenStatusFile)

	nsBody, err := proto.Marshal(&uipb.GetControlStreamResponse{
		Event: &uipb.GetControlStreamResponse_Namespaces{
			Namespaces: &uipb.GetControlStreamResponse_NamespaceStates{
				Namespaces: []*uipb.NamespaceState{
					{Namespace: &uipb.NamespaceDescriptor{Name: "payments"}},
					{Namespace: &uipb.NamespaceDescriptor{Name: "kube-system"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := testProxy(false).filterBody(route, channel, nsBody, scopeOf("payments"), identity.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	resp := &uipb.GetControlStreamResponse{}
	if err := proto.Unmarshal(out, resp); err != nil {
		t.Fatal(err)
	}
	got := resp.GetNamespaces().GetNamespaces()
	if len(got) != 1 || got[0].GetNamespace().GetName() != "payments" {
		t.Errorf("got %v, want only payments", got)
	}
}
