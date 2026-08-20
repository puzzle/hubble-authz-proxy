// Package registry remembers, per client channel, which namespace each service
// ID belongs to. ui.ServiceLink names its endpoints by opaque ID and carries no
// namespace, so an edge can only be resolved against announcements seen earlier
// on the same channel.
package registry

import (
	"context"
	"sync"
	"time"

	"github.com/puzzle/hubble-authz-proxy/internal/metrics"
)

// Registry remembers which namespace each service map node belongs to.
//
// It exists because ui.ServiceLink identifies its endpoints by opaque service
// ID (source_id / destination_id) and carries no namespace of its own. The only
// place a service's namespace appears is the ui.ServiceState event that
// announces it, which may have been delivered on an *earlier* poll. So we record
// every service we see — including ones the caller is not allowed to see, since
// we still need their namespace to decide that links touching them must be
// dropped.
//
// State is keyed by customprotocol channel ID, which is the backend's per-client
// stream identity, so one user's service map never informs another's. Channels
// are swept after an idle period because clients abandon them silently.
//
// The channel count is bounded as well as swept. A page reload, a navigation or
// a namespace switch each mint a fresh channel and abandon the old one, so on
// the TTL alone a busy UI accumulates one cluster-sized service map per
// abandoned session for the whole idle period. That is the same unbounded-growth
// shape as reading a response body without a limit, and the same failure:
// an OOMKill that takes Hubble UI down for everyone.
type Registry struct {
	ttl         time.Duration
	maxChannels int
	now         func() time.Time

	mu       sync.Mutex
	channels map[string]*channelServices
}

// DefaultMaxChannels is generous next to real use — one channel per active
// browser tab — while still capping worst-case memory at a few tens of MB.
const DefaultMaxChannels = 1024

type channelServices struct {
	lastSeen   time.Time
	namespaces map[string]string // service ID -> namespace ("" is a real value: world/reserved)
	// peers holds service IDs outside the caller's scope that are on the far end
	// of a link from inside it. They are recorded per service rather than per
	// namespace so that a namespace with ten services only exposes the one
	// actually talking to the caller.
	peers map[string]bool
	// emptyScopeNotified records that this channel has already been told its
	// caller can see nothing. The UI's Status Center does not deduplicate — the
	// backend is what dedupes its own NoPermission notices — so without this the
	// user collects one identical warning per poll, forever.
	emptyScopeNotified bool
}

// New builds a registry holding per-channel state for ttl. maxChannels caps how
// many channels are tracked before the least recently used is dropped; 0 or less
// disables the cap entirely (see makeRoomLocked), which is what --max-channels=0
// selects. Callers wanting the default pass DefaultMaxChannels explicitly.
func New(ttl time.Duration, maxChannels int) *Registry {
	return &Registry{
		ttl:         ttl,
		maxChannels: maxChannels,
		now:         time.Now,
		channels:    map[string]*channelServices{},
	}
}

// Remember records a service ID's namespace for this channel.
func (r *Registry) Remember(channelID, serviceID, namespace string) {
	if channelID == "" || serviceID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ch := r.channelLocked(channelID)
	ch.lastSeen = r.now()
	ch.namespaces[serviceID] = namespace
}

// channelLocked returns the channel's state, creating it if needed. Caller holds
// r.mu.
func (r *Registry) channelLocked(channelID string) *channelServices {
	ch := r.channels[channelID]
	if ch == nil {
		r.makeRoomLocked()
		ch = &channelServices{
			namespaces: map[string]string{},
			peers:      map[string]bool{},
		}
		r.channels[channelID] = ch
		metrics.TrackedChannels.Set(float64(len(r.channels)))
	}
	return ch
}

// makeRoomLocked ensures there is space for one more channel. Caller holds r.mu.
//
// Expired channels go first, since dropping those costs nothing. Only if the
// registry is still full of live channels does it evict the least recently seen.
//
// Evicting a live channel is safe but not free: the caller's next poll finds its
// service IDs unknown, and unknown endpoints are failed closed, so some links
// vanish from their map until the backend re-announces those services. That is
// the right trade against an OOMKill, and it is why the eviction is counted —
// a nonzero rate means --max-channels is too low for the number of concurrent
// sessions, not that anything is wrong with the filter.
func (r *Registry) makeRoomLocked() {
	if r.maxChannels <= 0 || len(r.channels) < r.maxChannels {
		return
	}

	cutoff := r.now().Add(-r.ttl)
	for id, ch := range r.channels {
		if ch.lastSeen.Before(cutoff) {
			delete(r.channels, id)
		}
	}
	if len(r.channels) < r.maxChannels {
		return
	}

	for len(r.channels) >= r.maxChannels {
		var oldestID string
		var oldest time.Time
		for id, ch := range r.channels {
			if oldestID == "" || ch.lastSeen.Before(oldest) {
				oldestID, oldest = id, ch.lastSeen
			}
		}
		if oldestID == "" {
			return
		}
		delete(r.channels, oldestID)
		metrics.ChannelEvictionsTotal.Inc()
	}
}

// RememberPeer records a service the caller may see because it is linked to one
// inside their scope, even though its own namespace is not.
func (r *Registry) RememberPeer(channelID, serviceID string) {
	if channelID == "" || serviceID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ch := r.channelLocked(channelID)
	ch.lastSeen = r.now()
	ch.peers[serviceID] = true
}

// MarkEmptyScopeNotified reports whether this channel still needs to be told
// that its caller can see nothing, and records that it has been.
//
// Returns true exactly once per channel. A channel evicted under --max-channels
// and then seen again is told a second time, which is the right side to err on:
// repeating a warning is a nuisance, never showing it is the bug this exists to
// fix.
func (r *Registry) MarkEmptyScopeNotified(channelID string) bool {
	if channelID == "" {
		// No channel to remember against, so sending it every poll would spam.
		// The UI always supplies one past the first response.
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ch := r.channelLocked(channelID)
	ch.lastSeen = r.now()
	if ch.emptyScopeNotified {
		return false
	}
	ch.emptyScopeNotified = true
	return true
}

// IsPeer reports whether this service was recorded as linked to the caller's
// scope on this channel.
func (r *Registry) IsPeer(channelID, serviceID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	ch := r.channels[channelID]
	if ch == nil {
		return false
	}
	return ch.peers[serviceID]
}

// Lookup returns the namespace recorded for a service ID. The second result
// distinguishes "known to live in no namespace" (world, reserved) from "never
// announced on this channel" — callers must fail closed on the latter, since an
// unknown endpoint could be anywhere.
func (r *Registry) Lookup(channelID, serviceID string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ch := r.channels[channelID]
	if ch == nil {
		return "", false
	}
	ch.lastSeen = r.now()
	ns, ok := ch.namespaces[serviceID]
	return ns, ok
}

// sweep drops channels that have been idle for longer than the TTL.
func (r *Registry) sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := r.now().Add(-r.ttl)
	for id, ch := range r.channels {
		if ch.lastSeen.Before(cutoff) {
			delete(r.channels, id)
		}
	}
	metrics.TrackedChannels.Set(float64(len(r.channels)))
}

// RunSweeper sweeps periodically until ctx is cancelled.
func (r *Registry) RunSweeper(ctx context.Context) {
	t := time.NewTicker(r.ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.sweep()
		}
	}
}
