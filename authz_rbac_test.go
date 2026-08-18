package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type fakeCluster struct {
	authz  *RBACAuthorizer
	client *fake.Clientset
	sars   *atomic.Int64
	// beforeSAR, when set, runs before each review is answered. Used to hold
	// reviews open so concurrency is observable.
	beforeSAR func()
	sarErr    error
	mu        sync.Mutex
}

// newFakeCluster builds an RBACAuthorizer over a fake API server where the
// caller may list pods exactly in allowedNamespaces.
func newFakeCluster(t *testing.T, namespaces []string, allowedNamespaces []string, ttl time.Duration) *fakeCluster {
	t.Helper()

	objs := make([]runtime.Object, 0, len(namespaces))
	for _, ns := range namespaces {
		objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	allowed := map[string]bool{}
	for _, ns := range allowedNamespaces {
		allowed[ns] = true
	}

	fc := &fakeCluster{sars: &atomic.Int64{}}
	client := fake.NewClientset(objs...)
	client.PrependReactor("create", "subjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			fc.sars.Add(1)
			fc.mu.Lock()
			hook, err := fc.beforeSAR, fc.sarErr
			fc.mu.Unlock()
			if hook != nil {
				hook()
			}
			if err != nil {
				return true, nil, err
			}
			sar, ok := action.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
			if !ok {
				return true, nil, errors.New("unexpected object")
			}
			sar.Status.Allowed = allowed[sar.Spec.ResourceAttributes.Namespace]
			return true, sar, nil
		})

	fc.authz = newRBACAuthorizer(client, ttl)
	fc.client = client
	return fc
}

func cacheHasKey(fc *fakeCluster, id Identity) bool {
	fc.authz.mu.Lock()
	defer fc.authz.mu.Unlock()
	_, ok := fc.authz.cache[cacheKey(id)]
	return ok
}

// waitFor polls cond until it is true, matching the sleep-and-deadline
// convention already used for the RunReloader goroutine tests (authz_test.go)
// rather than a fake clock — RunWatch's own eventual consistency (informer
// sync, then event dispatch) is real, not simulated.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (fc *fakeCluster) setHook(f func()) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.beforeSAR = f
}

func (fc *fakeCluster) setErr(err error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.sarErr = err
}

var testIdentity = Identity{Email: "bob@example.com", Groups: []string{"team-payments"}}

func TestRBACResolvesAllowedNamespaces(t *testing.T) {
	fc := newFakeCluster(t,
		[]string{"payments", "search", "kube-system"},
		[]string{"payments"}, time.Minute)

	scope, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if scope.All {
		t.Error("rbac mode must never grant unrestricted scope")
	}
	if len(scope.Namespaces) != 1 || !scope.Namespaces["payments"] {
		t.Errorf("scope = %v, want {payments}", scope.Namespaces)
	}
	// One cluster-scoped probe, then one review per namespace.
	if got := fc.sars.Load(); got != 1+3 {
		t.Errorf("issued %d reviews, want 1 cluster-scoped + 3 namespaced", got)
	}
}

func TestRBACCachesByIdentity(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments", "search"}, []string{"payments"}, time.Minute)

	for range 5 {
		if _, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity); err != nil {
			t.Fatal(err)
		}
	}
	if got := fc.sars.Load(); got != 1+2 {
		t.Errorf("issued %d reviews across 5 calls, want 3 (one sweep, then cached)", got)
	}
}

// The reason singleflight is here: without it, N concurrent requests for the
// same cold identity each fan out a full sweep over every namespace.
func TestRBACSingleflightCollapsesConcurrentMisses(t *testing.T) {
	const namespaces = 10
	nsNames := make([]string, namespaces)
	for i := range nsNames {
		nsNames[i] = string(rune('a'+i)) + "-ns"
	}
	fc := newFakeCluster(t, nsNames, []string{"a-ns"}, time.Minute)

	// Hold every review until all callers are in flight, so they genuinely race.
	release := make(chan struct{})
	fc.setHook(func() { <-release })

	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = fc.authz.AllowedNamespaces(context.Background(), testIdentity)
		}()
	}

	// Give the goroutines time to pile up on the same key before unblocking.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := fc.sars.Load(); got != 1+namespaces {
		t.Errorf("issued %d reviews for 20 concurrent callers, want %d (a single sweep)", got, 1+namespaces)
	}
}

func TestRBACReResolvesAfterTTL(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments", "search"}, []string{"payments"}, time.Minute)

	now := time.Now()
	fc.authz.now = func() time.Time { return now }

	if _, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity); err != nil {
		t.Fatal(err)
	}
	first := fc.sars.Load()

	now = now.Add(2 * time.Minute)
	if _, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity); err != nil {
		t.Fatal(err)
	}
	if fc.sars.Load() != first*2 {
		t.Errorf("expired entry was not re-resolved: %d reviews total, want %d", fc.sars.Load(), first*2)
	}
}

// A partial sweep would look like a smaller namespace set — an under-show that
// then gets cached — so any failing review must fail the whole resolution.
func TestRBACReviewErrorFailsClosed(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments", "search"}, []string{"payments"}, time.Minute)
	fc.setErr(errors.New("apiserver unavailable"))

	if _, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity); err == nil {
		t.Fatal("want an error when a SubjectAccessReview fails")
	}

	// And the failure must not be cached as an empty scope.
	fc.setErr(nil)
	scope, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Namespaces["payments"] {
		t.Error("a failed resolution was cached; recovery never happened")
	}
}

func TestRBACCacheIsBounded(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	fc.authz.maxCache = 8

	// Every distinct identity that reaches the proxy creates an entry, and the
	// identity is caller-supplied, so the map must not grow without bound.
	for i := range 100 {
		id := Identity{Email: string(rune('a'+i%26)) + string(rune('a'+i/26)) + "@example.com"}
		if _, err := fc.authz.AllowedNamespaces(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}

	fc.authz.mu.Lock()
	size := len(fc.authz.cache)
	fc.authz.mu.Unlock()
	if size > fc.authz.maxCache {
		t.Errorf("cache holds %d entries, want <= %d", size, fc.authz.maxCache)
	}
}

func TestRBACSweepDropsExpired(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	now := time.Now()
	fc.authz.now = func() time.Time { return now }

	if _, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	fc.authz.sweep()

	fc.authz.mu.Lock()
	size := len(fc.authz.cache)
	fc.authz.mu.Unlock()
	if size != 0 {
		t.Errorf("sweep left %d expired entries", size)
	}
}

// Group order comes from HTTP headers and is not guaranteed stable; keying on
// the raw order would duplicate entries and re-run the sweep for each variant.
func TestRBACCacheKeyIgnoresGroupOrder(t *testing.T) {
	a := Identity{Email: "bob@example.com", Groups: []string{"team-search", "team-payments"}}
	b := Identity{Email: "bob@example.com", Groups: []string{"team-payments", "team-search"}}
	if cacheKey(a) != cacheKey(b) {
		t.Errorf("cacheKey differs by group order:\n %q\n %q", cacheKey(a), cacheKey(b))
	}

	// Different identities must still be distinguished, including when a group
	// name could be confused with a boundary.
	c := Identity{Email: "bob@example.com", Groups: []string{"team-payments"}}
	if cacheKey(b) == cacheKey(c) {
		t.Error("cacheKey collided across different group sets")
	}
	d := Identity{User: "bob@example.com"}
	if cacheKey(c) == cacheKey(d) {
		t.Error("cacheKey collided across user and email fields")
	}
}

// A caller who may list pods cluster-wide needs no filtering, so one review
// should answer it instead of sweeping every namespace — on a large cluster the
// admins are otherwise the most expensive users to resolve.
func TestRBACClusterWideShortCircuits(t *testing.T) {
	// metav1.NamespaceAll is "", so allowing that means "in every namespace".
	fc := newFakeCluster(t,
		[]string{"payments", "search", "kube-system"},
		[]string{""}, time.Minute)

	scope, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.All {
		t.Fatalf("cluster-wide caller got a scoped result: %v", scope.Namespaces)
	}
	if got := fc.sars.Load(); got != 1 {
		t.Errorf("issued %d reviews, want 1 — the per-namespace sweep should be skipped", got)
	}
}

// Scope{All} must not be a frozen snapshot: an unrestricted caller keeps seeing
// namespaces created after their cache entry was written.
func TestRBACClusterWideScopeHasNoNamespaceSnapshot(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{""}, time.Minute)

	scope, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if len(scope.Namespaces) != 0 {
		t.Errorf("enumerated %v alongside All; filtering is skipped so this is dead state", scope.Namespaces)
	}
}

// --- watch-driven invalidation ---------------------------------------------

func subject(kind, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: kind, APIGroup: "rbac.authorization.k8s.io", Name: name}
}

// startWatch runs RunWatch in the background and gives the fake informers a
// moment to complete their initial list before the test starts mutating
// objects — the same sleep-based synchronization already used in
// TestRBACSingleflightCollapsesConcurrentMisses, since fake-clientset sync is
// in-memory and near-instant.
func startWatch(t *testing.T, fc *fakeCluster) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		fc.authz.RunWatch(ctx, testLogger())
		close(done)
	}()
	// Cleanup must not just signal cancellation — it has to wait for RunWatch to
	// actually return. Otherwise its goroutine can outlive this test and race the
	// next test's writes to package-level test knobs like rbacWatchSyncTimeout.
	t.Cleanup(func() {
		cancel()
		<-done
	})
	time.Sleep(100 * time.Millisecond)
	return ctx
}

func TestRBACWatchRoleBindingAddInvalidatesMatchingUser(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	alice := Identity{User: "alice"}
	if _, err := fc.authz.AllowedNamespaces(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	if !cacheHasKey(fc, alice) {
		t.Fatal("cache did not warm for alice")
	}

	ctx := startWatch(t, fc)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "payments"},
		Subjects:   []rbacv1.Subject{subject("User", "alice")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "viewer"},
	}
	if _, err := fc.client.RbacV1().RoleBindings("payments").Create(ctx, rb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return !cacheHasKey(fc, alice) })
}

func TestRBACWatchRoleBindingDeleteInvalidatesRemovedSubject(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "payments"},
		Subjects:   []rbacv1.Subject{subject("User", "alice")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "viewer"},
	}
	if _, err := fc.client.RbacV1().RoleBindings("payments").Create(context.Background(), rb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// The watch starts before the cache is warmed, matching production (RunWatch
	// runs continuously from proxy startup, well before any request populates the
	// cache): otherwise the informer's initial-sync replay of this pre-existing
	// RoleBinding would itself evict the entry before Delete is ever exercised.
	ctx := startWatch(t, fc)

	alice := Identity{User: "alice"}
	if _, err := fc.authz.AllowedNamespaces(ctx, alice); err != nil {
		t.Fatal(err)
	}

	if err := fc.client.RbacV1().RoleBindings("payments").Delete(ctx, "grant", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return !cacheHasKey(fc, alice) })
}

func TestRBACWatchRoleBindingUpdateInvalidatesOldAndNewSubjects(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "payments"},
		Subjects:   []rbacv1.Subject{subject("User", "alice")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "viewer"},
	}
	if _, err := fc.client.RbacV1().RoleBindings("payments").Create(context.Background(), rb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// See the comment in TestRBACWatchRoleBindingDeleteInvalidatesRemovedSubject:
	// the watch must start, and its initial-sync replay settle, before the cache
	// is warmed.
	ctx := startWatch(t, fc)

	alice := Identity{User: "alice"}
	bob := Identity{User: "bob"}
	if _, err := fc.authz.AllowedNamespaces(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.authz.AllowedNamespaces(ctx, bob); err != nil {
		t.Fatal(err)
	}

	cur, err := fc.client.RbacV1().RoleBindings("payments").Get(ctx, "grant", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cur.Subjects = []rbacv1.Subject{subject("User", "bob")}
	if _, err := fc.client.RbacV1().RoleBindings("payments").Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return !cacheHasKey(fc, alice) && !cacheHasKey(fc, bob) })
}

func TestRBACWatchClusterRoleUpdateInvalidatesBoundSubjects(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	cr := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "viewer"}}
	if _, err := fc.client.RbacV1().ClusterRoles().Create(context.Background(), cr, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant-team"},
		Subjects:   []rbacv1.Subject{subject("Group", "team-a")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "viewer"},
	}
	if _, err := fc.client.RbacV1().ClusterRoleBindings().Create(context.Background(), crb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant-carol", Namespace: "payments"},
		Subjects:   []rbacv1.Subject{subject("User", "carol")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "viewer"},
	}
	if _, err := fc.client.RbacV1().RoleBindings("payments").Create(context.Background(), rb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Start the watch (and let its initial-sync replay of these pre-existing
	// bindings settle) before warming the cache, matching production ordering —
	// see the comment in TestRBACWatchRoleBindingDeleteInvalidatesRemovedSubject.
	ctx := startWatch(t, fc)

	teamA := Identity{Groups: []string{"team-a"}}
	carol := Identity{User: "carol"}
	if _, err := fc.authz.AllowedNamespaces(ctx, teamA); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.authz.AllowedNamespaces(ctx, carol); err != nil {
		t.Fatal(err)
	}

	cur, err := fc.client.RbacV1().ClusterRoles().Get(ctx, "viewer", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cur.Labels = map[string]string{"bumped": "true"}
	if _, err := fc.client.RbacV1().ClusterRoles().Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return !cacheHasKey(fc, teamA) && !cacheHasKey(fc, carol) })
}

// Regression test: a Role only binds within its own namespace, so editing
// Role "foo" in namespace a must not invalidate a subject bound only via a
// same-named, but unrelated, Role "foo" living in namespace b.
func TestRBACWatchRoleUpdateRespectsNamespace(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	ctxBg := context.Background()
	roleA := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "a"}}
	roleB := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "b"}}
	if _, err := fc.client.RbacV1().Roles("a").Create(ctxBg, roleA, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.client.RbacV1().Roles("b").Create(ctxBg, roleB, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rbA := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "a"},
		Subjects:   []rbacv1.Subject{subject("User", "xavier")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "foo"},
	}
	rbB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "b"},
		Subjects:   []rbacv1.Subject{subject("User", "yolanda")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "foo"},
	}
	if _, err := fc.client.RbacV1().RoleBindings("a").Create(ctxBg, rbA, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.client.RbacV1().RoleBindings("b").Create(ctxBg, rbB, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Start the watch (and let its initial-sync replay of these pre-existing
	// bindings settle) before warming the cache, matching production ordering —
	// see the comment in TestRBACWatchRoleBindingDeleteInvalidatesRemovedSubject.
	ctx := startWatch(t, fc)

	xavier := Identity{User: "xavier"}
	yolanda := Identity{User: "yolanda"}
	if _, err := fc.authz.AllowedNamespaces(ctx, xavier); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.authz.AllowedNamespaces(ctx, yolanda); err != nil {
		t.Fatal(err)
	}

	cur, err := fc.client.RbacV1().Roles("a").Get(ctx, "foo", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cur.Labels = map[string]string{"bumped": "true"}
	if _, err := fc.client.RbacV1().Roles("a").Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return !cacheHasKey(fc, xavier) })

	time.Sleep(300 * time.Millisecond)
	if !cacheHasKey(fc, yolanda) {
		t.Error("editing namespace a's Role foo evicted namespace b's unrelated Role foo's subject")
	}
}

func TestRBACWatchNamespaceDeleteInvalidatesContainingEntries(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments", "search"}, nil, time.Minute)

	scoped := Identity{User: "scoped"}
	admin := Identity{User: "admin"}
	future := time.Now().Add(time.Hour)
	fc.authz.mu.Lock()
	fc.authz.cache[cacheKey(scoped)] = cachedScope{
		scope:   Scope{Namespaces: map[string]bool{"payments": true}},
		expires: future,
		id:      scoped,
	}
	fc.authz.cache[cacheKey(admin)] = cachedScope{
		scope:   Scope{All: true},
		expires: future,
		id:      admin,
	}
	fc.authz.mu.Unlock()

	ctx := startWatch(t, fc)
	if err := fc.client.CoreV1().Namespaces().Delete(ctx, "payments", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return !cacheHasKey(fc, scoped) })

	time.Sleep(300 * time.Millisecond)
	if !cacheHasKey(fc, admin) {
		t.Error("deleting a namespace evicted an All-scoped entry, which has nothing stale to drop")
	}
}

// RunWatch must never block the authorizer: if the ServiceAccount lacks
// watch/list on the RBAC group (e.g. an old Helm chart), it degrades to
// TTL-only within a bound and the SAR/cache path underneath keeps working
// exactly as it does with -rbac-watch=false.
func TestRBACWatchDegradesGracefullyWithoutPermission(t *testing.T) {
	orig := rbacWatchSyncTimeout
	rbacWatchSyncTimeout = 100 * time.Millisecond
	t.Cleanup(func() { rbacWatchSyncTimeout = orig })

	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	fc.client.PrependReactor("list", "roles", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		fc.authz.RunWatch(ctx, testLogger())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunWatch did not degrade to TTL-only within the sync timeout")
	}

	scope, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity)
	if err != nil {
		t.Fatalf("SAR/TTL path broken after watch degraded: %v", err)
	}
	if !scope.Namespaces["payments"] {
		t.Errorf("scope = %v, want {payments} — watch degradation must not affect resolution", scope.Namespaces)
	}
}

// Giving up has to actually stop the reflectors. They retry a denied list
// forever with backoff, logging at error level through klog — straight to
// stderr, bypassing -log-format — so a factory left running after RunWatch
// returns turns "one warning, then TTL-only" into permanent error spam and a
// permanent trickle of 403s at the apiserver.
func TestRBACWatchDegradedPathStopsInformers(t *testing.T) {
	orig := rbacWatchSyncTimeout
	rbacWatchSyncTimeout = 100 * time.Millisecond
	t.Cleanup(func() { rbacWatchSyncTimeout = orig })

	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	var attempts atomic.Int64
	fc.client.PrependReactor("list", "roles", func(k8stesting.Action) (bool, runtime.Object, error) {
		attempts.Add(1)
		return true, nil, errors.New("forbidden")
	})

	// Deliberately NOT cancelled before the assertion: this must hold while the
	// process context is still alive, which is the production case.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		fc.authz.RunWatch(ctx, testLogger())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunWatch did not return within the sync timeout")
	}
	settled := attempts.Load()

	time.Sleep(1500 * time.Millisecond)
	if got := attempts.Load(); got != settled {
		t.Errorf("informers kept retrying after RunWatch gave up: %d attempts at return, %d after 1.5s",
			settled, got)
	}
}

// The five watches are only affordable if what they cache is bounded to what
// the invalidation logic reads. Rancher-style clusters generate RBAC per
// project, so an aggregated ClusterRole's rules plus managedFields and
// last-applied-configuration on every object is the difference between a small
// cache and an unbounded one.
func TestTrimForWatchCacheDropsUnreadFields(t *testing.T) {
	bulky := metav1.ObjectMeta{
		Name:          "x",
		Namespace:     "ns",
		Labels:        map[string]string{"keep": "me"},
		Annotations:   map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{...}"},
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
	}

	cr, err := trimForWatchCache(&rbacv1.ClusterRole{
		ObjectMeta:      bulky,
		Rules:           []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
		AggregationRule: &rbacv1.AggregationRule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := cr.(*rbacv1.ClusterRole)
	if got.Rules != nil || got.AggregationRule != nil {
		t.Error("ClusterRole rules/aggregationRule are never read but were kept")
	}
	if got.Annotations != nil || got.ManagedFields != nil {
		t.Error("annotations/managedFields are never read but were kept")
	}
	// Labels stay: the listers select on them, so dropping them would leave a
	// future List(selector) silently matching nothing.
	if got.Labels["keep"] != "me" {
		t.Error("labels were dropped; a label-selector lookup would silently match nothing")
	}
	if got.Name != "x" {
		t.Errorf("name = %q, want x — the reverse lookup matches on it", got.Name)
	}

	// A binding's RoleRef and Subjects are exactly what invalidation reads.
	rb, err := trimForWatchCache(&rbacv1.RoleBinding{
		ObjectMeta: bulky,
		Subjects:   []rbacv1.Subject{subject("User", "alice")},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "viewer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotRB := rb.(*rbacv1.RoleBinding)
	if len(gotRB.Subjects) != 1 || gotRB.Subjects[0].Name != "alice" {
		t.Errorf("subjects = %v, want alice retained", gotRB.Subjects)
	}
	if gotRB.RoleRef.Name != "viewer" {
		t.Errorf("roleRef = %v, want viewer retained", gotRB.RoleRef)
	}

	// An unrecognised type must pass through rather than error: a transform that
	// fails an object makes the informer drop the event entirely.
	pod := &corev1.Pod{ObjectMeta: bulky}
	out, err := trimForWatchCache(pod)
	if err != nil {
		t.Fatalf("transform failed an unrecognised type: %v", err)
	}
	if out != any(pod) {
		t.Error("an unrecognised type was not passed through untouched")
	}
}

func TestRBACWatchIrrelevantEventLeavesCacheWarm(t *testing.T) {
	fc := newFakeCluster(t, []string{"payments"}, []string{"payments"}, time.Minute)
	if _, err := fc.authz.AllowedNamespaces(context.Background(), testIdentity); err != nil {
		t.Fatal(err)
	}
	before := fc.sars.Load()

	ctx := startWatch(t, fc)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "payments"},
		Subjects:   []rbacv1.Subject{subject("User", "someone-else")},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "viewer"},
	}
	if _, err := fc.client.RbacV1().RoleBindings("payments").Create(ctx, rb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)
	if !cacheHasKey(fc, testIdentity) {
		t.Error("an unrelated RoleBinding evicted the cached entry")
	}
	if fc.sars.Load() != before {
		t.Error("an unrelated RoleBinding triggered a re-resolution")
	}
}
