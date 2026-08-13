package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"sigs.k8s.io/yaml"
)

// Scope is the set of namespaces a caller may see. All=true means unrestricted
// (cluster-admin) — filtering is skipped entirely for that caller.
type Scope struct {
	All        bool
	Namespaces map[string]bool
}

type Authorizer interface {
	AllowedNamespaces(ctx context.Context, id Identity) (Scope, error)
}

// --- static mapping --------------------------------------------------------

// mapping is loaded from a ConfigMap-mounted YAML file. Example:
//
//	admins:
//	  - platform-admins            # group
//	  - alice@example.com          # user email
//	groupToNamespaces:
//	  team-payments:               # OIDC group
//	    - payments
//	    - payments-staging
//	userToNamespaces:
//	  bob@example.com:
//	    - sandbox-bob
type mapping struct {
	Admins    []string            `json:"admins"`
	GroupToNS map[string][]string `json:"groupToNamespaces"`
	UserToNS  map[string][]string `json:"userToNamespaces"`
}

// StaticAuthorizer resolves scope from a file, and re-reads that file while
// running.
//
// Reloading is not a convenience. The mapping is normally a ConfigMap, and
// kubelet updates the mounted file in place — so without this, granting a team
// a namespace appears to work (the ConfigMap changes, the file in the pod
// changes) and silently does nothing until someone restarts the pod. Revoking
// access has the same delay, which is the direction that matters.
//
// The chart's checksum annotation only ever covered half of it: it is skipped
// when authz.existingConfigMap is set, which is exactly what GitOps and secret
// tooling use.
type StaticAuthorizer struct {
	path string
	log  *slog.Logger

	mu  sync.RWMutex
	m   mapping
	sum [sha256.Size]byte
}

func NewStaticAuthorizer(path string, logger *slog.Logger) (*StaticAuthorizer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	a := &StaticAuthorizer{path: path, log: logger}
	// Startup is the one place a bad mapping must be fatal: serving with no
	// mapping at all would silently deny everyone.
	if _, err := a.reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// reload re-reads the mapping, reporting whether the contents changed.
//
// Compares a content hash rather than mtime or size: a ConfigMap update swaps
// the ..data symlink the mount points through, and mtime semantics across that
// swap are not something to bet access control on.
func (a *StaticAuthorizer) reload() (bool, error) {
	b, err := os.ReadFile(a.path)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(b)

	a.mu.RLock()
	unchanged := sum == a.sum
	a.mu.RUnlock()
	if unchanged {
		return false, nil
	}

	var m mapping
	if err := yaml.Unmarshal(b, &m); err != nil {
		return false, fmt.Errorf("parse %s: %w", a.path, err)
	}

	a.mu.Lock()
	a.m, a.sum = m, sum
	a.mu.Unlock()
	return true, nil
}

// RunReloader re-reads the mapping every interval until ctx is cancelled.
//
// A failed reload KEEPS THE LAST GOOD MAPPING. The alternative — dropping to an
// empty mapping — would turn a half-written file or a transient read error into
// a cluster-wide lockout, and the file is being written by something else while
// we read it. The trade is that a bad edit leaves the previous rules in force,
// including a revocation that has not applied, so the failure is loud: an error
// log plus mapping_reloads_total{result="error"}, and
// mapping_last_reload_timestamp_seconds stops advancing. Alert on the latter.
func (a *StaticAuthorizer) RunReloader(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		a.log.Info("mapping hot-reload disabled; changes need a pod restart",
			"path", a.path)
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := a.reload()
			if err != nil {
				mappingReloads.WithLabelValues(reloadError).Inc()
				a.log.Error("cannot reload mapping; keeping the previous one",
					"path", a.path, "err", err)
				continue
			}
			if !changed {
				mappingReloads.WithLabelValues(reloadUnchanged).Inc()
				mappingLastReload.SetToCurrentTime()
				continue
			}
			mappingReloads.WithLabelValues(reloadChanged).Inc()
			mappingLastReload.SetToCurrentTime()

			// Counts, not contents: enough to confirm the edit landed without
			// writing everyone's namespace assignments into the log.
			a.mu.RLock()
			m := a.m
			a.mu.RUnlock()
			a.log.Info("mapping reloaded",
				"path", a.path,
				"admins", len(m.Admins),
				"groups", len(m.GroupToNS),
				"users", len(m.UserToNS))
		}
	}
}

func (a *StaticAuthorizer) AllowedNamespaces(_ context.Context, id Identity) (Scope, error) {
	a.mu.RLock()
	m := a.m
	a.mu.RUnlock()

	if contains(m.Admins, id.User) || contains(m.Admins, id.Email) {
		return Scope{All: true}, nil
	}
	for _, g := range id.Groups {
		if contains(m.Admins, g) {
			return Scope{All: true}, nil
		}
	}

	ns := map[string]bool{}
	for _, n := range m.UserToNS[id.User] {
		ns[n] = true
	}
	for _, n := range m.UserToNS[id.Email] {
		ns[n] = true
	}
	for _, g := range id.Groups {
		for _, n := range m.GroupToNS[g] {
			ns[n] = true
		}
	}
	return Scope{Namespaces: ns}, nil
}

func contains(list []string, s string) bool {
	if s == "" {
		return false
	}
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
