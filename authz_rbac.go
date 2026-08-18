package main

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rbacv1listers "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/rest"
)

// Defaults for RBACAuthorizer tuning.
const (
	defaultSARConcurrency = 16
	defaultMaxCacheSize   = 2048
)

// RBACAuthorizer derives the visible namespace set from real cluster RBAC: for
// each namespace it asks the API server, on behalf of the caller, whether they
// may "list pods". This keeps the Hubble view in lockstep with kubectl access
// and needs no mapping to maintain.
//
// A resolution costs one SubjectAccessReview per namespace, which is why three
// things guard it:
//
//   - results are cached per identity for ttl;
//   - singleflight collapses concurrent misses for the same identity, so a cold
//     cache under load issues one sweep rather than one per in-flight request;
//   - the sweep itself runs concurrency reviews in parallel, turning an
//     O(namespaces) serial latency into roughly O(namespaces/concurrency).
//
// The cache is bounded and swept, because its keys are attacker-influenced:
// every distinct user/group combination that reaches the proxy creates an entry.
//
// The proxy's ServiceAccount needs: create on subjectaccessreviews, list on
// namespaces. RunWatch (authz_rbac_watch.go) additionally wants watch on
// namespaces and list/watch on roles/clusterroles/rolebindings/
// clusterrolebindings, to evict a cached entry sooner than ttl when access
// changes — but that is a latency optimization, not a requirement: without it
// RunWatch logs a warning and the authorizer keeps working on ttl alone.
type RBACAuthorizer struct {
	kc          kubernetes.Interface
	ttl         time.Duration
	concurrency int
	maxCache    int
	now         func() time.Time

	group singleflight.Group

	mu    sync.Mutex
	cache map[string]cachedScope

	// Set once by RunWatch, before factory.Start() spawns the goroutines that
	// could invoke handlers referencing them; ordinary happens-before via the
	// go statement covers it, since AllowedNamespaces/resolve never touch them.
	roleBindingLister        rbacv1listers.RoleBindingLister
	clusterRoleBindingLister rbacv1listers.ClusterRoleBindingLister
}

type cachedScope struct {
	scope   Scope
	expires time.Time
	// id is the identity this entry was resolved for, retained so watch-driven
	// invalidation (authz_rbac_watch.go) can match cluster RBAC subjects
	// (User/Group) without re-parsing the opaque cacheKey string.
	id Identity
}

func NewRBACAuthorizer(ttl time.Duration, concurrency int) (*RBACAuthorizer, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	a := newRBACAuthorizer(kc, ttl)
	if concurrency > 0 {
		a.concurrency = concurrency
	}
	return a, nil
}

func newRBACAuthorizer(kc kubernetes.Interface, ttl time.Duration) *RBACAuthorizer {
	return &RBACAuthorizer{
		kc:          kc,
		ttl:         ttl,
		concurrency: defaultSARConcurrency,
		maxCache:    defaultMaxCacheSize,
		now:         time.Now,
		cache:       map[string]cachedScope{},
	}
}

func (a *RBACAuthorizer) AllowedNamespaces(ctx context.Context, id Identity) (Scope, error) {
	key := cacheKey(id)

	if scope, ok := a.cached(key); ok {
		scopeCacheTotal.WithLabelValues("hit").Inc()
		return scope, nil
	}
	scopeCacheTotal.WithLabelValues("miss").Inc()

	// singleflight dedupes concurrent misses for the same identity. Note it does
	// NOT inherit any one caller's context, so a client disconnecting mid-sweep
	// cannot cancel the resolution that other waiters are blocked on; the sweep
	// uses a context detached from cancellation but bounded by ttl.
	res, err, _ := a.group.Do(key, func() (any, error) {
		// Re-check: another goroutine may have populated the cache between our
		// lookup and joining the flight.
		if scope, ok := a.cached(key); ok {
			return scope, nil
		}
		sweepCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.ttl)
		defer cancel()

		scope, err := a.resolve(sweepCtx, id)
		if err != nil {
			return Scope{}, err
		}
		a.store(key, scope, id)
		return scope, nil
	})
	if err != nil {
		return Scope{}, err
	}
	return res.(Scope), nil
}

func (a *RBACAuthorizer) resolve(ctx context.Context, id Identity) (Scope, error) {
	// Ask the cluster-scoped question first. A caller who may list pods in every
	// namespace needs no filtering at all, so this collapses the whole sweep into
	// one review — and on a large cluster the admins are exactly the users who
	// would otherwise be most expensive to resolve.
	//
	// It is also more correct than enumerating: an unrestricted caller gets
	// Scope{All: true} and keeps seeing namespaces created after their entry was
	// cached, rather than a snapshot frozen at resolution time.
	all, err := a.canListPods(ctx, id, metav1.NamespaceAll)
	if err != nil {
		return Scope{}, err
	}
	if all {
		return Scope{All: true}, nil
	}

	nsList, err := a.kc.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return Scope{}, err
	}

	var mu sync.Mutex
	allowed := map[string]bool{}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(a.concurrency)
	for i := range nsList.Items {
		name := nsList.Items[i].Name
		g.Go(func() error {
			ok, err := a.canListPods(gctx, id, name)
			if err != nil {
				return err
			}
			if ok {
				mu.Lock()
				allowed[name] = true
				mu.Unlock()
			}
			return nil
		})
	}
	// Any review failing fails the whole resolution: a partial answer would look
	// like a smaller namespace set, which silently under-shows rather than
	// erroring, and would then be cached.
	if err := g.Wait(); err != nil {
		return Scope{}, err
	}
	return Scope{Namespaces: allowed}, nil
}

func (a *RBACAuthorizer) canListPods(ctx context.Context, id Identity, ns string) (bool, error) {
	sar := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   firstNonEmpty(id.User, id.Email),
			Groups: id.Groups,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: ns,
				Verb:      "list",
				Group:     "", // core
				Resource:  "pods",
			},
		},
	}
	subjectAccessReviewsTotal.Inc()
	res, err := a.kc.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return res.Status.Allowed, nil
}

func (a *RBACAuthorizer) cached(key string) (Scope, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	c, ok := a.cache[key]
	if !ok || !a.now().Before(c.expires) {
		return Scope{}, false
	}
	return c.scope, true
}

func (a *RBACAuthorizer) store(key string, scope Scope, id Identity) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.cache) >= a.maxCache {
		a.evictExpiredLocked()
		// Still full of live entries: drop arbitrary ones rather than grow without
		// bound. Losing an entry only costs a re-resolution.
		for k := range a.cache {
			if len(a.cache) < a.maxCache {
				break
			}
			delete(a.cache, k)
		}
	}
	a.cache[key] = cachedScope{scope: scope, expires: a.now().Add(a.ttl), id: id}
}

func (a *RBACAuthorizer) evictExpiredLocked() {
	now := a.now()
	for k, c := range a.cache {
		if !now.Before(c.expires) {
			delete(a.cache, k)
		}
	}
}

// sweep drops expired entries so idle identities do not pin memory.
func (a *RBACAuthorizer) sweep() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.evictExpiredLocked()
}

// RunSweeper evicts expired cache entries until ctx is cancelled.
func (a *RBACAuthorizer) RunSweeper(ctx context.Context) {
	t := time.NewTicker(a.ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.sweep()
		}
	}
}

// cacheKey identifies a caller. Groups are sorted so that an identity presenting
// the same groups in a different header order reuses its entry instead of
// duplicating one (and triggering a fresh SAR sweep).
func cacheKey(id Identity) string {
	groups := append([]string(nil), id.Groups...)
	slices.Sort(groups)
	return id.User + "\x00" + id.Email + "\x00" + strings.Join(groups, "\x00")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
