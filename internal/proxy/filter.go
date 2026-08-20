package proxy

import (
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// namespacePairVisible is the single visibility rule used everywhere: given the
// two namespaces an item connects, may a caller scoped to `allowed` see it?
//
// An empty namespace means "owned by nobody" — the host, the world/internet,
// reserved identities, remote nodes.
//
// Default (requireBoth=false): visible if EITHER end is in an allowed namespace,
// i.e. you can see what your namespace talks to even when the peer is elsewhere.
// This necessarily reveals the peer's namespace name; if that is unacceptable,
// set requireBoth=true, which shows only intra-scope traffic (plus traffic to
// non-namespaced entities like the internet).
func namespacePairVisible(src, dst string, allowed map[string]bool, requireBoth bool) bool {
	srcOK := src != "" && allowed[src]
	dstOK := dst != "" && allowed[dst]

	if requireBoth {
		srcOKorEmpty := src == "" || allowed[src]
		dstOKorEmpty := dst == "" || allowed[dst]
		return srcOKorEmpty && dstOKorEmpty && (srcOK || dstOK)
	}
	return srcOK || dstOK
}

// flowVisible reports whether a caller scoped to `allowed` may see this flow.
func flowVisible(f *flowpb.Flow, allowed map[string]bool, requireBoth bool) bool {
	return namespacePairVisible(
		f.GetSource().GetNamespace(),
		f.GetDestination().GetNamespace(),
		allowed, requireBoth,
	)
}
