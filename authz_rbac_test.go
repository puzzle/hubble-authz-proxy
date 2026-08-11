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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type fakeCluster struct {
	authz *RBACAuthorizer
	sars  *atomic.Int64
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
	return fc
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
