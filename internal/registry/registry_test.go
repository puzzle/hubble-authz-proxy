package registry

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/puzzle/hubble-authz-proxy/internal/metrics"
)

// fixedClock lets the tests drive lastSeen directly, so LRU order is asserted
// rather than raced against the wall clock.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestRegistry(ttl time.Duration, maxChannels int) (*Registry, *fixedClock) {
	clk := &fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	r := New(ttl, maxChannels)
	r.now = clk.now
	return r, clk
}

func TestRegistryCapsChannelCount(t *testing.T) {
	r, clk := newTestRegistry(time.Hour, 3)

	// Distinct, all live: nothing may be reclaimed for free.
	for _, id := range []string{"a", "b", "c"} {
		r.Remember(id, "svc-1", "ns-1")
		clk.advance(time.Second)
	}
	if got := len(r.channels); got != 3 {
		t.Fatalf("len(channels) = %d, want 3", got)
	}

	// A fourth must not grow past the cap.
	r.Remember("d", "svc-1", "ns-1")
	if got := len(r.channels); got > 3 {
		t.Errorf("len(channels) = %d, want <= 3; the cap is not enforced", got)
	}
	if _, ok := r.channels["d"]; !ok {
		t.Error("the newest channel was not admitted")
	}
	// "a" was the least recently seen, so it is the one that goes.
	if _, ok := r.channels["a"]; ok {
		t.Error("evicted a channel other than the least recently used")
	}
	for _, id := range []string{"b", "c"} {
		if _, ok := r.channels[id]; !ok {
			t.Errorf("channel %q was evicted while a less recently used one survived", id)
		}
	}
}

// Touching a channel must keep it alive: without this the cap would evict the
// session a user is actively looking at while keeping idle ones.
func TestRegistryEvictsLeastRecentlyUsedNotOldest(t *testing.T) {
	r, clk := newTestRegistry(time.Hour, 2)

	r.Remember("old", "svc-1", "ns-1")
	clk.advance(time.Second)
	r.Remember("new", "svc-1", "ns-1")
	clk.advance(time.Second)

	// "old" is the oldest by creation but the most recently *used*.
	if _, ok := r.Lookup("old", "svc-1"); !ok {
		t.Fatal("lookup did not find the service it just recorded")
	}
	clk.advance(time.Second)

	r.Remember("third", "svc-1", "ns-1")

	if _, ok := r.channels["old"]; !ok {
		t.Error("evicted the channel that was just read from; lastSeen is not tracking use")
	}
	if _, ok := r.channels["new"]; ok {
		t.Error("kept the least recently used channel")
	}
}

// Expired channels must be reclaimed before any live one is dropped, so a burst
// of new sessions after a quiet period costs nobody their service map.
func TestRegistryPrefersExpiredOverLive(t *testing.T) {
	r, clk := newTestRegistry(time.Minute, 2)

	r.Remember("stale", "svc-1", "ns-1")
	clk.advance(2 * time.Minute) // past the TTL
	r.Remember("live", "svc-1", "ns-1")

	r.Remember("fresh", "svc-1", "ns-1")

	if _, ok := r.channels["stale"]; ok {
		t.Error("the expired channel survived")
	}
	if _, ok := r.channels["live"]; !ok {
		t.Error("a live channel was evicted while an expired one was available")
	}
	if _, ok := r.channels["fresh"]; !ok {
		t.Error("the new channel was not admitted")
	}
}

func TestRegistryZeroMaxChannelsDisablesCap(t *testing.T) {
	r, _ := newTestRegistry(time.Hour, 0)

	for _, id := range []string{"a", "b", "c", "d", "e"} {
		r.Remember(id, "svc-1", "ns-1")
	}
	if got := len(r.channels); got != 5 {
		t.Errorf("len(channels) = %d, want 5; 0 must mean unlimited", got)
	}
}

// The gauge is what an operator alerts on, so it must track reality between
// sweeps rather than only after one. It previously only moved inside sweep(),
// which meant it read 0 for up to a full TTL after startup.
func TestRegistryGaugeUpdatesWithoutASweep(t *testing.T) {
	t.Cleanup(func() { metrics.TrackedChannels.Set(0) })

	r, _ := newTestRegistry(time.Hour, 10)
	r.Remember("a", "svc-1", "ns-1")
	r.Remember("b", "svc-1", "ns-1")

	if got := testutil.ToFloat64(metrics.TrackedChannels); got != 2 {
		t.Errorf("hubble_authz_tracked_channels = %v, want 2 before any sweep", got)
	}
}

// Evicting a live channel is a capacity signal an operator must be able to see;
// silently dropping state would look like the filter misbehaving.
func TestRegistryCountsEvictions(t *testing.T) {
	before := testutil.ToFloat64(metrics.ChannelEvictionsTotal)

	r, clk := newTestRegistry(time.Hour, 1)
	r.Remember("a", "svc-1", "ns-1")
	clk.advance(time.Second)
	r.Remember("b", "svc-1", "ns-1")

	if got := testutil.ToFloat64(metrics.ChannelEvictionsTotal) - before; got != 1 {
		t.Errorf("evictions counted = %v, want 1", got)
	}
}

// Peers are the lenient-mode visibility state; they must not outlive their
// channel or a later session could inherit another user's peer set.
func TestRegistryEvictionDropsPeers(t *testing.T) {
	r, clk := newTestRegistry(time.Hour, 1)

	r.RememberPeer("a", "svc-peer")
	if !r.IsPeer("a", "svc-peer") {
		t.Fatal("peer was not recorded")
	}
	clk.advance(time.Second)

	r.Remember("b", "svc-1", "ns-1") // evicts "a"

	if r.IsPeer("a", "svc-peer") {
		t.Error("peer state survived its channel's eviction")
	}
}
