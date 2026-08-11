package main

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func flowNS(src, dst string) *flowpb.Flow {
	f := &flowpb.Flow{}
	if src != "" {
		f.Source = &flowpb.Endpoint{Namespace: src}
	}
	if dst != "" {
		f.Destination = &flowpb.Endpoint{Namespace: dst}
	}
	return f
}

func TestFlowVisible(t *testing.T) {
	allowed := map[string]bool{"payments": true, "search": true}

	tests := []struct {
		name            string
		src, dst        string
		lenient, strict bool
	}{
		// Wholly inside the caller's scope.
		{"intra-scope", "payments", "payments", true, true},
		{"across two allowed namespaces", "payments", "search", true, true},

		// One foot in scope, one out: the case --require-both-endpoints exists for.
		// Lenient shows it (and thereby reveals the peer's namespace name).
		{"allowed to foreign", "payments", "secret-ns", true, false},
		{"foreign to allowed", "secret-ns", "payments", true, false},

		// Empty namespace = world/host/reserved, owned by nobody. Egress to the
		// internet stays visible even under the strict policy.
		{"allowed to world", "payments", "", true, true},
		{"world to allowed", "", "payments", true, true},

		// Nothing in scope at all.
		{"wholly foreign", "secret-ns", "other-ns", false, false},
		{"world to world", "", "", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := flowNS(tc.src, tc.dst)
			if got := flowVisible(f, allowed, false); got != tc.lenient {
				t.Errorf("flowVisible(requireBoth=false) = %v, want %v", got, tc.lenient)
			}
			if got := flowVisible(f, allowed, true); got != tc.strict {
				t.Errorf("flowVisible(requireBoth=true) = %v, want %v", got, tc.strict)
			}
		})
	}
}

// An empty scope must never be readable as "everything".
func TestFlowVisibleEmptyScope(t *testing.T) {
	for _, requireBoth := range []bool{false, true} {
		if flowVisible(flowNS("payments", "search"), map[string]bool{}, requireBoth) {
			t.Errorf("empty scope leaked a flow (requireBoth=%v)", requireBoth)
		}
		if flowVisible(flowNS("payments", "search"), nil, requireBoth) {
			t.Errorf("nil scope leaked a flow (requireBoth=%v)", requireBoth)
		}
	}
}

// A flow with no endpoint info at all must not be visible, so that a stripped or
// unparsed payload fails closed rather than open.
func TestFlowVisibleEmptyFlow(t *testing.T) {
	allowed := map[string]bool{"payments": true}
	for _, requireBoth := range []bool{false, true} {
		if flowVisible(&flowpb.Flow{}, allowed, requireBoth) {
			t.Errorf("empty flow was visible (requireBoth=%v)", requireBoth)
		}
	}
}
