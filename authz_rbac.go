package main

import (
	"context"
	"strings"
	"sync"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// RBACAuthorizer derives the visible namespace set from real cluster RBAC: for
// each namespace it asks the API server, on behalf of the caller, whether they
// may "list pods". This keeps the Hubble view in lockstep with kubectl access
// and needs no mapping to maintain.
//
// Cost: O(#namespaces) SubjectAccessReviews per cache miss, so results are
// cached per identity with a TTL. For large clusters prefer one of:
//   - watching RoleBindings/ClusterRoleBindings and precomputing group->ns;
//   - a SelfSubjectRulesReview using the caller's own token (needs the token
//     forwarded by oauth2-proxy AND the API server trusting that OIDC issuer).
//
// The proxy's ServiceAccount needs: create on subjectaccessreviews, list on
// namespaces.
type RBACAuthorizer struct {
	kc  kubernetes.Interface
	ttl time.Duration

	mu    sync.Mutex
	cache map[string]cachedScope
}

type cachedScope struct {
	scope   Scope
	expires time.Time
}

func NewRBACAuthorizer(ttl time.Duration) (*RBACAuthorizer, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &RBACAuthorizer{kc: kc, ttl: ttl, cache: map[string]cachedScope{}}, nil
}

func (a *RBACAuthorizer) AllowedNamespaces(ctx context.Context, id Identity) (Scope, error) {
	key := id.User + "|" + id.Email + "|" + strings.Join(id.Groups, ",")

	a.mu.Lock()
	if c, ok := a.cache[key]; ok && time.Now().Before(c.expires) {
		a.mu.Unlock()
		return c.scope, nil
	}
	a.mu.Unlock()

	nsList, err := a.kc.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return Scope{}, err
	}
	allowed := map[string]bool{}
	for i := range nsList.Items {
		name := nsList.Items[i].Name
		ok, err := a.canListPods(ctx, id, name)
		if err != nil {
			return Scope{}, err
		}
		if ok {
			allowed[name] = true
		}
	}
	scope := Scope{Namespaces: allowed}

	a.mu.Lock()
	a.cache[key] = cachedScope{scope: scope, expires: time.Now().Add(a.ttl)}
	a.mu.Unlock()
	return scope, nil
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
	res, err := a.kc.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return res.Status.Allowed, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
