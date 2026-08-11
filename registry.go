package main

import (
	"context"
	"sync"
	"time"
)

// serviceRegistry remembers which namespace each service map node belongs to.
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
type serviceRegistry struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	channels map[string]*channelServices
}

type channelServices struct {
	lastSeen   time.Time
	namespaces map[string]string // service ID -> namespace ("" is a real value: world/reserved)
}

func newServiceRegistry(ttl time.Duration) *serviceRegistry {
	return &serviceRegistry{
		ttl:      ttl,
		now:      time.Now,
		channels: map[string]*channelServices{},
	}
}

// remember records a service ID's namespace for this channel.
func (r *serviceRegistry) remember(channelID, serviceID, namespace string) {
	if channelID == "" || serviceID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ch := r.channels[channelID]
	if ch == nil {
		ch = &channelServices{namespaces: map[string]string{}}
		r.channels[channelID] = ch
	}
	ch.lastSeen = r.now()
	ch.namespaces[serviceID] = namespace
}

// lookup returns the namespace recorded for a service ID. The second result
// distinguishes "known to live in no namespace" (world, reserved) from "never
// announced on this channel" — callers must fail closed on the latter, since an
// unknown endpoint could be anywhere.
func (r *serviceRegistry) lookup(channelID, serviceID string) (string, bool) {
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
func (r *serviceRegistry) sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := r.now().Add(-r.ttl)
	for id, ch := range r.channels {
		if ch.lastSeen.Before(cutoff) {
			delete(r.channels, id)
		}
	}
	trackedChannels.Set(float64(len(r.channels)))
}

// RunSweeper sweeps periodically until ctx is cancelled.
func (r *serviceRegistry) RunSweeper(ctx context.Context) {
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
