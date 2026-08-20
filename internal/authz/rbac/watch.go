package rbac

import (
	"context"
	"log/slog"
	"time"

	"github.com/puzzle/hubble-authz-proxy/internal/metrics"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const (
	// 0 disables client-go's periodic full resync. Roles/bindings are pure spec
	// objects with no status subresource, so nothing but a real edit produces an
	// Update event; a synthetic timer resync would only relay no-op updates.
	// The TTL sweep remains the actual backstop for anything the watch misses.
	rbacWatchResyncPeriod = 0

	rbacKindUser  = "User"
	rbacKindGroup = "Group"
)

// rbacWatchSyncTimeout bounds how long RunWatch waits for the initial
// list+relist before giving up and degrading to TTL-only. A var (not a
// const) so tests can shrink it.
//
// It must not wait forever: ctx here is the whole-process lifetime context,
// cancelled only at shutdown. A reflector denied watch/list on these
// resources retries indefinitely with backoff and never flips HasSynced, so
// without this bound RunWatch — and the log line telling anyone why
// invalidation isn't working — would never return until process exit.
var rbacWatchSyncTimeout = 30 * time.Second

// RunWatch starts informers for Namespaces, Roles, ClusterRoles,
// RoleBindings and ClusterRoleBindings, and evicts matching cache entries on
// relevant changes — shrinking the AVERAGE staleness window below -rbac-ttl.
// It is a pure latency optimization: RunSweeper and the ttl remain the
// correctness backstop for anything missed here (a relist gap, a proxy
// restart mid-change, or the ServiceAccount simply lacking permission).
//
// RunWatch never blocks startup and never crashes the process: if the initial
// cache sync does not complete within rbacWatchSyncTimeout (missing RBAC
// permissions, apiserver unreachable, etc.) it logs a warning, STOPS THE
// INFORMERS and returns, leaving the authorizer running in TTL-only mode.
//
// Stopping them is the point of the derived context below. A reflector denied
// list/watch retries forever with backoff, and each failure logs at error level
// through klog — straight to stderr, bypassing -log-format. Leaving the factory
// running after giving up turns the documented "one warning, then TTL-only"
// into permanent error spam plus a permanent trickle of 403s at the apiserver,
// which is exactly what an operator sees when the image is upgraded ahead of
// the chart's RBAC rules.
func (a *Authorizer) RunWatch(ctx context.Context, logger *slog.Logger) {
	ctx, stopInformers := context.WithCancel(ctx)
	defer stopInformers()

	factory := informers.NewSharedInformerFactoryWithOptions(a.kc, rbacWatchResyncPeriod,
		informers.WithTransform(trimForWatchCache))

	nsInformer := factory.Core().V1().Namespaces().Informer()
	roleInformer := factory.Rbac().V1().Roles().Informer()
	clusterRoleInformer := factory.Rbac().V1().ClusterRoles().Informer()
	rbInformer := factory.Rbac().V1().RoleBindings().Informer()
	crbInformer := factory.Rbac().V1().ClusterRoleBindings().Informer()

	a.roleBindingLister = factory.Rbac().V1().RoleBindings().Lister()
	a.clusterRoleBindingLister = factory.Rbac().V1().ClusterRoleBindings().Lister()

	handlers := []struct {
		name     string
		informer cache.SharedIndexInformer
		funcs    cache.ResourceEventHandlerFuncs
	}{
		{"namespaces", nsInformer, cache.ResourceEventHandlerFuncs{
			// AddFunc intentionally unset: a new namespace only ever widens
			// access, and Scope{All:true} entries see it for free already (see
			// resolve()'s comment in rbac.go) — not a revocation concern.
			DeleteFunc: func(obj any) {
				ns, ok := unwrapTombstone(obj).(*corev1.Namespace)
				if !ok {
					return
				}
				a.invalidateNamespace(ns.Name)
			},
		}},
		{"roles", roleInformer, cache.ResourceEventHandlerFuncs{
			// AddFunc intentionally unset: a new Role only ever widens access —
			// nothing was cached against permissions that didn't exist yet.
			UpdateFunc: func(_, newObj any) {
				if r, ok := newObj.(*rbacv1.Role); ok {
					a.onRoleChanged(logger, r.Namespace, r.Name)
				}
			},
			DeleteFunc: func(obj any) {
				if r, ok := unwrapTombstone(obj).(*rbacv1.Role); ok {
					a.onRoleChanged(logger, r.Namespace, r.Name)
				}
			},
		}},
		{"clusterroles", clusterRoleInformer, cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(_, newObj any) {
				if cr, ok := newObj.(*rbacv1.ClusterRole); ok {
					a.onClusterRoleChanged(logger, cr.Name)
				}
			},
			DeleteFunc: func(obj any) {
				if cr, ok := unwrapTombstone(obj).(*rbacv1.ClusterRole); ok {
					a.onClusterRoleChanged(logger, cr.Name)
				}
			},
		}},
		{"rolebindings", rbInformer, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				if rb, ok := obj.(*rbacv1.RoleBinding); ok {
					a.invalidateSubjects(rb.Subjects, metrics.ResourceRoleBinding)
				}
			},
			UpdateFunc: func(oldObj, newObj any) {
				old, ok1 := oldObj.(*rbacv1.RoleBinding)
				cur, ok2 := newObj.(*rbacv1.RoleBinding)
				if !ok1 || !ok2 {
					return
				}
				// Both old and new subjects: a subject REMOVED from the binding
				// needs its stale ALLOW entry invalidated too.
				a.invalidateSubjects(append(append([]rbacv1.Subject{}, old.Subjects...), cur.Subjects...), metrics.ResourceRoleBinding)
			},
			DeleteFunc: func(obj any) {
				if rb, ok := unwrapTombstone(obj).(*rbacv1.RoleBinding); ok {
					a.invalidateSubjects(rb.Subjects, metrics.ResourceRoleBinding)
				}
			},
		}},
		{"clusterrolebindings", crbInformer, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				if crb, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
					a.invalidateSubjects(crb.Subjects, metrics.ResourceClusterRoleBinding)
				}
			},
			UpdateFunc: func(oldObj, newObj any) {
				old, ok1 := oldObj.(*rbacv1.ClusterRoleBinding)
				cur, ok2 := newObj.(*rbacv1.ClusterRoleBinding)
				if !ok1 || !ok2 {
					return
				}
				a.invalidateSubjects(append(append([]rbacv1.Subject{}, old.Subjects...), cur.Subjects...), metrics.ResourceClusterRoleBinding)
			},
			DeleteFunc: func(obj any) {
				if crb, ok := unwrapTombstone(obj).(*rbacv1.ClusterRoleBinding); ok {
					a.invalidateSubjects(crb.Subjects, metrics.ResourceClusterRoleBinding)
				}
			},
		}},
	}

	for _, h := range handlers {
		if _, err := h.informer.AddEventHandler(h.funcs); err != nil {
			logger.Warn("rbac watch: cannot register handler; continuing in TTL-only mode",
				"resource", h.name, "err", err)
			metrics.RBACWatchActive.Set(0)
			return
		}
	}

	factory.Start(ctx.Done())

	synced := make(chan bool, 1)
	go func() {
		synced <- cache.WaitForCacheSync(ctx.Done(),
			nsInformer.HasSynced, roleInformer.HasSynced, clusterRoleInformer.HasSynced,
			rbInformer.HasSynced, crbInformer.HasSynced)
	}()

	select {
	case ok := <-synced:
		if !ok {
			logger.Warn("rbac watch: cache sync did not complete; continuing in TTL-only mode")
			metrics.RBACWatchActive.Set(0)
			return
		}
	case <-time.After(rbacWatchSyncTimeout):
		logger.Warn("rbac watch: cache sync timed out; continuing in TTL-only mode "+
			"(likely missing watch/list RBAC on Roles/ClusterRoles/RoleBindings/ClusterRoleBindings/Namespaces)",
			"timeout", rbacWatchSyncTimeout)
		metrics.RBACWatchActive.Set(0)
		return
	case <-ctx.Done():
		return
	}

	logger.Info("rbac watch: cache-invalidation active")
	metrics.RBACWatchActive.Set(1)
	<-ctx.Done()
}

func unwrapTombstone(obj any) any {
	if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		return t.Obj
	}
	return obj
}

// trimForWatchCache drops everything the invalidation logic never reads before
// an object enters the informer cache, which is what stops these five watches
// from being an unbounded memory cost on a cluster with a lot of RBAC.
//
// Only three things are ever read: a binding's RoleRef and Subjects, a role's
// name/namespace, and a namespace's name. Everything else is dead weight, and
// the dead weight is the large part — .rules on an aggregated ClusterRole,
// managedFields on anything server-side-applied, and the
// last-applied-configuration annotation kubectl leaves behind (a second copy
// of the whole object). Clusters that generate RBAC per project or per
// namespace, Rancher among them, are where this matters most.
//
// Transforms run once per object on the way in, so the trimmed copy is what
// both the cache and the event handlers see. Mutating in place is safe here for
// the same reason: the informer hands the object over before anything else can
// observe it.
func trimForWatchCache(obj any) (any, error) {
	switch o := obj.(type) {
	case *corev1.Namespace:
		trimMeta(&o.ObjectMeta)
		o.Spec = corev1.NamespaceSpec{}
		o.Status = corev1.NamespaceStatus{}
	case *rbacv1.Role:
		trimMeta(&o.ObjectMeta)
		o.Rules = nil
	case *rbacv1.ClusterRole:
		trimMeta(&o.ObjectMeta)
		o.Rules = nil
		o.AggregationRule = nil
	case *rbacv1.RoleBinding:
		trimMeta(&o.ObjectMeta)
	case *rbacv1.ClusterRoleBinding:
		trimMeta(&o.ObjectMeta)
	}
	// Anything else (including a DeletedFinalStateUnknown tombstone) passes
	// through untouched: a transform must never fail an object it cannot
	// recognise, or the informer drops the event entirely.
	return obj, nil
}

// trimMeta clears the two metadata fields that actually carry weight. Labels
// are deliberately kept: they are small, and the listers select on them, so
// dropping them would leave a future List(selector) silently matching nothing.
func trimMeta(m *metav1.ObjectMeta) {
	m.ManagedFields = nil
	m.Annotations = nil
}

// onRoleChanged handles a Role update/delete: Roles carry no subjects
// themselves, so this looks up which RoleBindings IN THE SAME NAMESPACE
// reference it, and invalidates the union of their subjects in one pass.
// Namespace-scoped lookup matters: a Role only binds within its own
// namespace, so a same-named RoleBinding elsewhere references a DIFFERENT
// Role object entirely and must not be matched.
func (a *Authorizer) onRoleChanged(logger *slog.Logger, namespace, name string) {
	bindings, err := a.roleBindingLister.RoleBindings(namespace).List(labels.Everything())
	if err != nil {
		logger.Warn("rbac watch: reverse lookup failed; a stale entry may outlive this event (ttl backstop still applies)",
			"resource", metrics.ResourceRole, "namespace", namespace, "name", name, "err", err)
		return
	}
	var subjects []rbacv1.Subject
	for _, rb := range bindings {
		if rb.RoleRef.Kind == "Role" && rb.RoleRef.Name == name {
			subjects = append(subjects, rb.Subjects...)
		}
	}
	a.invalidateSubjects(subjects, metrics.ResourceRole)
}

// onClusterRoleChanged handles a ClusterRole update/delete: it may be
// referenced by RoleBindings in ANY namespace, plus ClusterRoleBindings.
// ClusterRole aggregation via aggregationRule needs no handling here: the API
// server itself rewrites the aggregate ClusterRole's .rules and emits its own
// Update event for that object.
func (a *Authorizer) onClusterRoleChanged(logger *slog.Logger, name string) {
	var subjects []rbacv1.Subject

	rbs, err := a.roleBindingLister.List(labels.Everything())
	if err != nil {
		logger.Warn("rbac watch: reverse lookup failed", "resource", metrics.ResourceClusterRole, "name", name, "err", err)
		return
	}
	for _, rb := range rbs {
		if rb.RoleRef.Kind == "ClusterRole" && rb.RoleRef.Name == name {
			subjects = append(subjects, rb.Subjects...)
		}
	}

	crbs, err := a.clusterRoleBindingLister.List(labels.Everything())
	if err != nil {
		logger.Warn("rbac watch: reverse lookup failed", "resource", metrics.ResourceClusterRole, "name", name, "err", err)
		return
	}
	for _, crb := range crbs {
		if crb.RoleRef.Kind == "ClusterRole" && crb.RoleRef.Name == name {
			subjects = append(subjects, crb.Subjects...)
		}
	}
	a.invalidateSubjects(subjects, metrics.ResourceClusterRole)
}

// invalidateSubjects evicts any cached entry belonging to one of the given
// RBAC subjects. Kind=ServiceAccount is ignored: this proxy's identities come
// from oauth2-proxy headers and are never ServiceAccount-shaped.
func (a *Authorizer) invalidateSubjects(subjects []rbacv1.Subject, resource string) {
	users, groups := map[string]bool{}, map[string]bool{}
	for _, s := range subjects {
		switch s.Kind {
		case rbacKindUser:
			users[s.Name] = true
		case rbacKindGroup:
			groups[s.Name] = true
		}
	}
	if len(users) == 0 && len(groups) == 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for k, c := range a.cache {
		subject := firstNonEmpty(c.id.User, c.id.Email)
		matched := users[subject]
		if !matched {
			for _, g := range c.id.Groups {
				if groups[g] {
					matched = true
					break
				}
			}
		}
		if matched {
			delete(a.cache, k)
			metrics.RBACCacheInvalidationsTotal.WithLabelValues(resource).Inc()
		}
	}
}

// invalidateNamespace evicts any cached entry whose resolved Scope includes
// ns. Scope{All: true} entries are left alone: resolve()'s cluster-wide
// short-circuit never enumerates namespaces, so an admin's cache entry has
// nothing stale to drop when one namespace disappears.
func (a *Authorizer) invalidateNamespace(ns string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, c := range a.cache {
		if !c.scope.All && c.scope.Namespaces[ns] {
			delete(a.cache, k)
			metrics.RBACCacheInvalidationsTotal.WithLabelValues(metrics.ResourceNamespace).Inc()
		}
	}
}
