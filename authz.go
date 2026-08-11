package main

import (
	"context"
	"os"

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

type StaticAuthorizer struct {
	m mapping
}

func NewStaticAuthorizer(path string) (*StaticAuthorizer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m mapping
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &StaticAuthorizer{m: m}, nil
}

func (a *StaticAuthorizer) AllowedNamespaces(_ context.Context, id Identity) (Scope, error) {
	if contains(a.m.Admins, id.User) || contains(a.m.Admins, id.Email) {
		return Scope{All: true}, nil
	}
	for _, g := range id.Groups {
		if contains(a.m.Admins, g) {
			return Scope{All: true}, nil
		}
	}

	ns := map[string]bool{}
	for _, n := range a.m.UserToNS[id.User] {
		ns[n] = true
	}
	for _, n := range a.m.UserToNS[id.Email] {
		ns[n] = true
	}
	for _, g := range id.Groups {
		for _, n := range a.m.GroupToNS[g] {
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
