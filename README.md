<!-- markdownlint-disable MD041 -->
![hubble-authz-proxy](doc/images/hubble-authz-proxy-logo.svg)

[![PR Quality](https://github.com/puzzle/hubble-authz-proxy/actions/workflows/pr-quality.yml/badge.svg)](https://github.com/puzzle/hubble-authz-proxy/actions/workflows/pr-quality.yml)
[![E2E](https://github.com/puzzle/hubble-authz-proxy/actions/workflows/e2e.yml/badge.svg)](https://github.com/puzzle/hubble-authz-proxy/actions/workflows/e2e.yml)
[![Release Please](https://github.com/puzzle/hubble-authz-proxy/actions/workflows/release-please.yml/badge.svg)](https://github.com/puzzle/hubble-authz-proxy/actions/workflows/release-please.yml)

Namespace-scoped authorization for the **Hubble UI** on **Cilium OSS**.

Hubble OSS has no tenancy: anyone who can reach the UI sees every flow in every
namespace. Cilium Enterprise ships Hubble RBAC as the paid answer. This is the
OSS equivalent — a small reverse proxy that sits between the Hubble UI frontend
and its backend, and removes from every response anything the logged-in user is
not entitled to see.

It does **authorization only**. Authentication is oauth2-proxy's job.

---

## How it works

```text
browser ──► ingress-nginx ─────────► hubble-ui frontend (nginx)
                 └─ auth_request ──►│  POST /api/…  + X-Auth-Request-* headers
                    oauth2-proxy    ▼
                            hubble-authz-proxy          ◄── this project
                                     │  same request, untouched
                                     ▼
                            hubble-ui backend (unmodified)
                                     │
                                     ▼
                               hubble-relay ──► hubble agents (eBPF)
```

The proxy is placed here for one reason: **this is the last hop that still knows
who the user is.** The hubble-ui backend opens its own connection to relay under
a machine identity and forwards nothing about the caller, so anything downstream
of it sees "the backend wants flows", never "*this user* wants flows".

Requests are relayed **untouched**. All enforcement is on the response, so a user
cannot widen their scope by crafting UI filters — whatever the backend sends back
is filtered against their namespace set before it reaches the browser.

### What gets filtered

The backend serves two routes, both carrying protobuf payloads inside a
`customprotocol.Message` envelope.

| Route | Payload | Treatment |
| --- | --- | --- |
| `control-stream` | `NamespaceState` | Only namespaces in scope, so the picker can't enumerate the cluster |
| `control-stream` | `Notification` | Passed through — cluster-wide status, but see [Known limitations](#known-limitations) |
| `control-stream` | *(empty scope)* | Replaced with a `NoPermission` notice so the user learns why the UI is blank |
| `service-map-stream` | `Flow`, `Flows` | Dropped unless an endpoint is in scope |
| `service-map-stream` | `ServiceState` | Kept when in scope, or when linked to something in scope (lenient only) |
| `service-map-stream` | `ServiceLinkState` | Both endpoint services resolved to namespaces, then the same rule |
| *anything else* | — | **Refused** (502), never forwarded |

Service-map edges are the awkward case: `ServiceLink` names its endpoints by
opaque service ID and carries no namespace. The proxy learns IDs from the
`ServiceState` events announcing them, keyed by the backend's per-client channel
ID. Two consequences worth knowing:

- The backend emits **link events before the service events** that name them, so
  each response is processed in two passes.
- An edge whose endpoints were never announced is **dropped**, not shown. An
  unknown endpoint could be anywhere.
- Under the lenient policy, a service *outside* your scope is shown once
  something inside your scope links to it — otherwise the flow table names the
  peer while the map has no node to draw, and the edge dangles at nothing. Only
  the linked service is exposed, not its whole namespace, and strict mode does
  not do this at all. It reveals nothing new: a visible flow already carries the
  peer's namespace, labels, pod name, workloads and identity, so the `Service`
  adds only `dns_names`, the policy-enforcement flags and a creation timestamp.

---

## Security model

**Read this before deploying.** The proxy trusts the `X-Auth-Request-*` headers
on every request it receives. It has no way to tell a header set by oauth2-proxy
from one set by a curious pod. Three things make that safe, and all three are
required:

1. **Only the authenticating pod may reach the proxy.** This is what
   `networkPolicy.enabled` is for. Without it, any workload in the cluster can
   set those headers itself and read every namespace. Reachability *is* the
   authentication boundary here.
2. **Every trusted header must be overwritten at the ingress**, via
   `auth-response-headers`. Anything not listed there is forwarded straight from
   the client. See [oauth2-proxy](#oauth2-proxy).
3. **The hubble-ui backend must not be reachable directly.** Bypassing the proxy
   bypasses the filtering entirely.

Point 3 deserves care. The ui-backend binds `0.0.0.0`, so it is reachable at
`podIP:<port>` from anywhere in the cluster no matter which mode you run — and
reaching it directly skips the proxy entirely, no headers needed.

In **standalone** mode the chart owns that pod, so `networkPolicy.enabled=true`
covers the backend and the proxy together: admitting only the ingress controller
to the frontend port leaves no route to either. In **proxy-only** mode the
backend lives in Cilium's pod, which this chart does not manage and therefore
cannot police — you must add that policy yourself.

Everything in the proxy fails closed. An unknown route, an unrecognised event
kind, an unparseable payload, or a missing scope all produce a 502 with no body
rather than a pass-through.

---

## Install

```console
helm repo add hubble-authz-proxy https://puzzle.github.io/hubble-authz-proxy
helm repo update
helm install hubble-authz-proxy hubble-authz-proxy/hubble-authz-proxy \
  --namespace kube-system \
  --values values.yaml
```

### Two modes

**Standalone (`hubbleUI.enabled=true`) — recommended.** The chart deploys Hubble
UI itself, with the proxy as a sidecar on the loopback path:

```text
frontend :8081 ──/api──► authz-proxy :8090 ──► ui-backend :8091 ──► relay
└──────────────────── one pod ────────────────────┘
```

Set `hubble.ui.enabled=false` in Cilium. Nothing else to wire.

Optionally add oauth2-proxy as a fourth container
(`hubbleUI.oauth2Proxy.enabled=true`) so the pod authenticates itself, with no
ingress middleware involved:

```text
ingress ──► oauth2-proxy :4180 ──► frontend :8081 ──/api──► authz-proxy ──► ui-backend ──► relay
            └────────────────────────── one pod ──────────────────────────┘
```

> **The header family changes with it.** As the reverse proxy, oauth2-proxy emits
> `X-Forwarded-User/-Email/-Groups`, *not* `X-Auth-Request-*` — that family only
> appears with `--set-xauthrequest`, which sets **response** headers for an
> `auth_request` subrequest. The chart sets the proxy's
> `--identity-header-prefix` to match, so the two cannot drift; if you wire this
> by hand and get it wrong, every request arrives anonymous and is refused.

**Proxy-only (default).** Cilium keeps its Hubble UI and you repoint its `/api`
at this proxy, as described below.

> **Why standalone is recommended.** Cilium owns the `hubble-ui-nginx` ConfigMap,
> so proxy-only mode means editing a resource Cilium will overwrite. A
> `helm upgrade cilium` silently restores the direct path to the backend —
> filtering stops, nothing errors, nothing restarts, and every user quietly sees
> every namespace again. Standalone mode removes that failure mode, and lets the
> chart ship the NetworkPolicy for the pod instead of asking you to add one to a
> Deployment it does not manage.

In proxy-only mode, install it in the **same namespace as hubble-ui** — the chart
creates a Service that selects the hubble-ui pod to expose the backend sidecar,
and a Service can only select pods in its own namespace.

A minimal `values.yaml`:

```yaml
authz:
  mode: static
  mapping:
    admins:
      - platform-admins
    groupToNamespaces:
      team-payments:
        - payments
        - payments-staging
      team-search:
        - search

networkPolicy:
  enabled: true
  ingressFrom:
    - podSelector:
        matchLabels:
          k8s-app: hubble-ui
```

### Wiring the frontend to the proxy

Installing the chart does not put the proxy in the data path. Cilium renders the
frontend's nginx config into the `hubble-ui-nginx` ConfigMap containing:

```nginx
location /api {
    proxy_http_version 1.1;
    proxy_pass_request_headers on;
    proxy_pass http://127.0.0.1:8090;   # the backend sidecar
}
```

Repoint that at the proxy's Service:

```nginx
    proxy_pass http://hubble-authz-proxy.kube-system.svc.cluster.local:8090;
```

then `kubectl rollout restart deployment/hubble-ui`.

> **A Cilium chart upgrade rewrites that ConfigMap**, silently restoring the
> direct path to the backend. Manage the override with a Helm post-renderer, or
> add a check to your upgrade runbook. `proxy_pass_request_headers on` must stay
> — that is what carries the identity headers through.

### oauth2-proxy

The proxy reads `X-Auth-Request-User`, `-Email` and `-Groups`. Those headers only
exist in nginx **`auth_request` mode**. Running oauth2-proxy as a reverse proxy
in front of hubble-ui instead sends `X-Forwarded-*`, which this proxy does not
read — you would get 401s.

**1. Install oauth2-proxy** on its own hostname:

```console
helm repo add oauth2-proxy https://oauth2-proxy.github.io/manifests
helm install oauth2-proxy oauth2-proxy/oauth2-proxy \
  --namespace kube-system --values oauth2-proxy-values.yaml
```

```yaml
# oauth2-proxy-values.yaml
config:
  clientID: hubble-ui
  clientSecret: "<from your IdP>"
  # Must be 16, 24 or 32 bytes:
  #   openssl rand -base64 32 | tr -- '+/' '-_'
  cookieSecret: "<generated>"

# NOTE: a map, not a list. Keys are flag names without the leading --.
extraArgs:
  provider: oidc
  oidc-issuer-url: https://keycloak.example.com/realms/main
  set-xauthrequest: "true"                 # emit the X-Auth-Request-* headers
  scope: "openid email profile groups"     # groups must be in the token
  email-domain: "*"                        # default rejects every login
  reverse-proxy: "true"                    # trust the ingress's X-Forwarded-*
  upstream: "static://202"                 # auth_request only; no real upstream
  cookie-domain: ".example.com"            # share the cookie with the UI host
  whitelist-domain: ".example.com"         # allow redirect back to it

ingress:
  enabled: true
  hosts:
    - oauth2-proxy.example.com
```

`email-domain` and the two domain settings are the usual causes of a login loop:
the default `email-domain` rejects every user, and without the cookie/whitelist
domains the session is set on the oauth2-proxy host and never seen by the UI
host.

**2. Point the hubble-ui ingress at it:**

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "https://oauth2-proxy.example.com/oauth2/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://oauth2-proxy.example.com/oauth2/start?rd=$escaped_request_uri"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-Request-User,X-Auth-Request-Email,X-Auth-Request-Groups"
```

**Every header this proxy trusts must be listed in `auth-response-headers`.**
That annotation compiles to, per header:

```nginx
auth_request_set $authHeader0 $upstream_http_x_auth_request_user;
proxy_set_header 'X-Auth-Request-User' $authHeader0;
```

`proxy_set_header` **overwrites** whatever the client sent, which is what makes
the header trustworthy — a browser cannot forge it. Headers *not* on that list
are forwarded from the client untouched. So omitting `X-Auth-Request-Groups`
does not mean "no groups"; it means the user supplies their own, and picks their
own namespaces. List all three.

That covers spoofing through the front door. It does not cover reaching the proxy
directly, which is what `networkPolicy.ingressFrom` is for — see
[Security model](#security-model).

#### Using Rancher as the OIDC provider

Rancher can act as its own OIDC provider ([docs][rancher-oidc]), issuing tokens
for whatever login Rancher itself is federated with (AD/LDAP, SAML, Keycloak,
GitHub, Entra/Azure AD, …) instead of pointing oauth2-proxy at that upstream
IdP directly.

**1. Register an `OIDCClient` in Rancher.** The `groups` scope is **not** one of
the defaults (`openid`, `profile`, `offline_access`) — it must be listed
explicitly or Rancher rejects it:

```yaml
apiVersion: management.cattle.io/v3
kind: OIDCClient
metadata:
  name: hubble-ui
spec:
  description: "hubble-authz-proxy / oauth2-proxy"
  redirectUris:
    - "https://oauth2-proxy.example.com/oauth2/callback"
  scopes:
    - openid
    - profile
    - groups
  tokenExpirationSeconds: 3600
  refreshTokenExpirationSeconds: 86400
```

Rancher generates the client ID/secret and stores them in a Secret in the
`cattle-oidc-client-secrets` namespace — read them from there for the
oauth2-proxy values below.

**2. Point oauth2-proxy at Rancher's issuer:**

```yaml
# oauth2-proxy-values.yaml
config:
  clientID: "<from cattle-oidc-client-secrets>"
  clientSecret: "<from cattle-oidc-client-secrets>"
  cookieSecret: "<generated>"

extraArgs:
  provider: oidc
  oidc-issuer-url: https://rancher.example.com/oidc
  set-xauthrequest: "true"
  scope: "openid profile groups"     # must match OIDCClient.spec.scopes
  email-domain: "*"
  reverse-proxy: "true"
  upstream: "static://202"
  cookie-domain: ".example.com"
  whitelist-domain: ".example.com"
```

Rancher has no `email` claim/scope, so oauth2-proxy's `X-Auth-Request-Email`
header comes back empty — key `mapping.yaml` off `X-Auth-Request-User` (the
Rancher `sub`, e.g. `u-cuk6luiram`) or off groups instead.

**3. Expect raw principal strings in `groups`, not friendly names.** Rancher's
OIDC provider only strips a `local://` prefix; whatever prefix the underlying
auth provider uses passes straight through — `activedirectory_group://` for
AD/LDAP, `openldap_group://`, `keycloakoidc_group://`, `github_team://`,
`azuread_group://`, `saml_group://`, and so on. The `groups` claim carries the
same values `kubectl auth whoami` shows, e.g. for an AD-backed login:

```text
activedirectory_group://CN=Admin,OU=my-ou,OU=my-group,DC=my-company,DC=tld
```

`groupToNamespaces` in `mapping.yaml` has to key on those full strings — a
group rename or, for AD/LDAP, an OU reorg, will change them and silently break
the mapping:

```yaml
groupToNamespaces:
  "activedirectory_group://CN=Admin,OU=my-ou,OU=my-group,DC=my-company,DC=tld":
    - payments
    - payments-staging
```

[rancher-oidc]: https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/configure-oidc-provider

---

## Configuration

### Authorization modes

**`static`** — a ConfigMap mapping OIDC groups and users to namespaces. Fast to
ship, but drifts from real cluster access.

```yaml
admins:                        # see everything, unfiltered
  - platform-admins
  - alice@example.com
groupToNamespaces:
  team-payments: [payments, payments-staging]
userToNamespaces:
  bob@example.com: [sandbox-bob]
```

The file is **re-read every `authz.reloadInterval`** (30s), so granting or
revoking access takes effect without restarting anything. kubelet updates a
mounted ConfigMap in place, so without this an edit *appears* to work — the
ConfigMap changes, the file inside the pod changes — and does nothing until the
pod restarts. Revocations are delayed the same way, which is the direction that
matters. kubelet's own sync period (~1 min by default) is the real floor on how
fast an edit can arrive; polling faster does not help.

A failed read or an unparseable file **keeps the previous mapping**. A
half-written file must not become a cluster-wide lockout, and the file is being
written by something else while we read it, so a torn read is ordinary rather
than exceptional. The trade is that a bad edit leaves the old rules in force —
including a revocation that has not applied — so the failure is made loud:

```promql
# Reloads failing, or the reloader itself stopped. Either way the mapping in
# force is not the one in the ConfigMap.
time() - hubble_authz_mapping_last_reload_timestamp_seconds > 300

# What went wrong.
sum(rate(hubble_authz_mapping_reloads_total{result="error"}[5m])) > 0
```

Alert on the **timestamp**, not just the error counter: a reloader goroutine
that died stops incrementing every series, which a `rate()` cannot see.

`authz.checksumAnnotation` still rolls the Deployment on a mapping change, but
is applied **only when `reloadInterval: 0`** — with hot-reload on, restarting
every pod is pure disruption, since it kills the long-poll requests the UI holds
open. It also never covered `authz.existingConfigMap`, which is what GitOps and
secret tooling use; hot-reload does.

A bad mapping at **startup** is still fatal. Coming up with no mapping would
silently deny everyone, which looks like an outage with no cause.

**`rbac`** — asks the API server, per namespace, whether the caller may `list
pods` there, via `SubjectAccessReview`. Tracks real `kubectl` access with no
mapping to maintain.

A caller who may list pods **cluster-wide** costs exactly one review — they get
unrestricted scope and filtering is skipped entirely. Everyone else needs one
review per namespace, so three things guard that:

- results are cached per identity for `authz.cacheTTL` (the cache is bounded and
  swept, since its keys come from caller-supplied headers);
- **singleflight** collapses concurrent misses for the same identity — a cold
  cache under load issues one sweep, not one per in-flight request;
- the sweep runs 16 reviews in parallel, so latency is roughly
  `namespaces / 16` round trips rather than `namespaces`.

If any single review fails, the whole resolution fails. A partial answer would
look like a smaller namespace set — an under-show that then gets cached — so it
errors instead, and failures are never cached.

**Sizing.** Steady-state load is `active users × namespaces` reviews per
`authz.cacheTTL`. On a cluster with a few hundred namespaces the 60s default is
the wrong end of the trade — raise `authz.cacheTTL` to `5m` or more, which cuts
the rate proportionally and costs you up to that long to notice revoked access.
Watch `hubble_authz_subjectaccessreviews_total` and
`hubble_authz_scope_cache_total{result="miss"}` to see what it actually costs
you before tuning further.

**Revocation latency.** `authz.watchRBAC` (on by default) watches Namespaces,
Roles, ClusterRoles, RoleBindings and ClusterRoleBindings and evicts a caller's
cached scope as soon as a change naming them is observed, instead of waiting out
`authz.cacheTTL`. This shrinks the *average* staleness window rather than
capping the worst case — the TTL still backstops whatever a watch misses (a
relist gap, a restart mid-change) — which is what makes raising
`authz.cacheTTL` for the sizing reason above cheaper than it looks.

It costs `list`/`watch` on those four resources plus `watch` on namespaces,
granted by the chart only while `authz.watchRBAC` is set, so turning the feature
off also drops the permissions. Missing them is never fatal: the proxy logs one
warning, stops the watches and falls back to TTL-only, visible as
`hubble_authz_rbac_watch_active` sitting at `0`. That is what an image upgraded
ahead of the chart's RBAC rules does, so a version skew degrades quietly instead
of failing.

What the informers cache is trimmed to what invalidation actually reads (a
binding's `roleRef` and `subjects`, a role's name, a namespace's name), so
`.rules`, `managedFields` and `last-applied-configuration` never accumulate in
memory. Clusters that generate RBAC per project or per namespace — Rancher among
them — are where that matters.

Note that `rbac` mode grants what `list pods` grants. If a team can read pods in
a namespace they can see its flows — usually what you want, but check it matches
your intent before assuming it is stricter than a static mapping.

### Cross-namespace visibility

A flow has two endpoints, so any flow touching your namespace reveals the peer's
namespace name. `proxy.requireBothEndpoints` decides the trade:

| | Behaviour |
| --- | --- |
| `false` (default) | Show it if **either** endpoint is in scope — you see what your namespace talks to, and learn peer namespace names |
| `true` | Only **intra-scope** traffic, plus traffic to non-namespaced entities (world, host, reserved identities) |

Namespaces are matched exactly; an empty namespace means "owned by nobody" and is
never a match on its own.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `:8090` | Listen address |
| `--backend` | `http://hubble-ui-backend:8090` | Upstream hubble-ui backend base URL |
| `--api-prefix` | `/api` | Paths under this are filtered and require identity; everything else passes through |
| `--authz` | `static` | `static` or `rbac` |
| `--authz-config` | `/etc/hubble-authz/mapping.yaml` | Static mapping file |
| `--authz-config-reload` | `30s` | How often the mapping file is re-read; `0` disables and makes changes need a restart |
| `--rbac-ttl` | `60s` | Cache TTL for a resolved namespace set |
| `--rbac-watch` | `true` | Watch Namespaces/Roles/ClusterRoles/RoleBindings/ClusterRoleBindings to evict a cached scope sooner than `--rbac-ttl` when access changes; falls back to TTL-only if the ServiceAccount lacks watch permission |
| `--channel-ttl` | `10m` | How long per-channel service-map state survives an idle client |
| `--max-channels` | `1024` | Cap on channels holding service-map state; past it the least recently used is dropped. `0` disables |
| `--notify-empty-scope` | `true` | Tell a caller with no visible namespaces why the UI is empty, instead of leaving it blank |
| `--require-both-endpoints` | `false` | Strict cross-namespace policy |
| `--metrics-listen` | `:9090` | Serves `/metrics` and `/healthz`; empty disables it |
| `--max-response-bytes` | `8388608` | Largest response the proxy will buffer to filter; oversized ones are refused |
| `--log-level` | `info` | `debug` logs the identity and resolved scope of every request |
| `--log-format` | `text` | `text` or `json` |
| `--shutdown-timeout` | `20s` | Grace period for in-flight requests after SIGTERM |

---

## Observability

Metrics and health are served on a **separate port** (`:9090` by default), never
on the proxy port. Reaching the proxy port is what authenticates a caller, so
exposing anything unauthenticated there would widen the trust boundary — and
scraping it would mean admitting Prometheus through the NetworkPolicy that is
supposed to admit only the authenticating pod. Scraping therefore needs its own
rule, `networkPolicy.metricsIngressFrom`; leaving it empty blocks Prometheus.

| Metric | Type | Labels |
| --- | --- | --- |
| `hubble_authz_requests_total` | counter | `route`, `outcome` |
| `hubble_authz_request_duration_seconds` | histogram | `route` |
| `hubble_authz_events_total` | counter | `kind`, `decision` |
| `hubble_authz_scope_resolution_seconds` | histogram | `mode` |
| `hubble_authz_scope_cache_total` | counter | `result` |
| `hubble_authz_subjectaccessreviews_total` | counter | — |
| `hubble_authz_rbac_watch_active` | gauge | — |
| `hubble_authz_rbac_cache_invalidations_total` | counter | `resource` |
| `hubble_authz_tracked_channels` | gauge | — |
| `hubble_authz_channel_evictions_total` | counter | — |
| `hubble_authz_empty_scope_notifications_total` | counter | — |
| `hubble_authz_mapping_reloads_total` | counter | `result` |
| `hubble_authz_mapping_last_reload_timestamp_seconds` | gauge | — |
| `hubble_authz_build_info` | gauge | `version` |

All label values come from fixed sets, never from request contents, so a caller
cannot inflate cardinality. Every known series is exported at zero on startup —
otherwise a `rate()` over `decision="dropped"` returns no data until the first
drop, which reads as "the filter isn't running" exactly when it is.

Useful starting points:

```promql
# Nothing is being filtered — often means every user resolves to an empty scope,
# or that admins are bypassing.
sum(rate(hubble_authz_events_total{decision="dropped"}[5m])) == 0

# Callers arriving without identity headers: oauth2-proxy or nginx misconfigured.
sum(rate(hubble_authz_requests_total{outcome="unauthenticated"}[5m])) > 0

# rbac mode falling out of cache and hammering the API server.
sum(rate(hubble_authz_subjectaccessreviews_total[5m]))
```

Set `metrics.serviceMonitor.enabled=true` if you run prometheus-operator.

### Response size

Filtering requires the whole body in memory — it is decoded, filtered and
re-encoded — so peak usage is roughly `--max-response-bytes` times the number of
callers polling at once. Keep it well under the pod's memory limit.

Service-map responses are the large ones and grow with cluster size; a few
hundred KB is ordinary. A response over the limit is **refused with 502, never
forwarded unfiltered or truncated**, and counted as:

```promql
sum(rate(hubble_authz_requests_total{outcome="response_too_large"}[5m]))
```

Any hit there means the limit needs raising, or the cluster has outgrown what
one response can carry — it is a configured bound, not a fault, which is why it
is a separate outcome from `upstream_error`.

### Retained per-client state

The proxy holds a service-ID → namespace map per client channel, because
`ServiceLink` names its endpoints by opaque ID and the announcing `ServiceState`
event may have arrived on an earlier poll. A reload, a navigation or a namespace
switch each start a fresh channel and abandon the old one, so `--channel-ttl`
alone lets a busy UI accumulate one cluster-sized map per abandoned session.

`--max-channels` bounds that, dropping the least recently used first — expired
channels before live ones. Evicting a *live* channel is safe but not free: that
client's next poll finds its service IDs unknown, and unknown endpoints are
failed closed, so some links disappear from their map until the backend
re-announces those services.

```promql
# Live sessions being dropped: --max-channels is too low for the concurrency.
sum(rate(hubble_authz_channel_evictions_total[5m])) > 0

# Which version is actually running.
hubble_authz_build_info
```

### Scaling out

**This state is per pod, so the proxy is stateful per client.** Spread one
client's polls across replicas and the pod handling this one never saw the
announcements — links vanish from the service map at random, with nothing logged
and no error raised. It looks like Hubble being flaky rather than a
misconfiguration, which is why the chart **refuses to render** with
`replicaCount > 1` unless `service.sessionAffinity` (or
`hubbleUI.service.sessionAffinity` in standalone mode) is `ClientIP`.

Service-level affinity is necessary but not always sufficient: an ingress
controller that load-balances straight to pod IPs — Traefik and Cilium's own
ingress can — bypasses `sessionAffinity` entirely and needs its own stickiness.
`replicaCount: 1` is the configuration with no such caveat, and for a component
in front of a monitoring UI it is usually the right one.

### "This user sees nothing"

By default the user is now told, so the report should arrive already diagnosed.
A caller whose scope resolves to no namespaces gets a warning in hubble-ui's
Status Center instead of a blank picker:

```text
You have no permissions to watch over "namespaces" resource

No namespaces are visible to bob@example.com (groups: devs, staff). Hubble
access is granted per namespace by hubble-authz-proxy; ask an administrator to
grant this user or one of these groups access.
```

Naming the identity is the point: it distinguishes "authentication is not
reaching the proxy" from "this subject has nothing mapped to it", and it hands
an admin the exact user or group to add. An empty group list in that message is
itself a strong hint that the authenticator is not passing groups.

Sent **once per channel**, since the Status Center does not deduplicate. Counted
by `hubble_authz_empty_scope_notifications_total` — a rising rate means people
are reaching Hubble with nothing mapped to them, which is worth knowing before
they open a ticket. It fires only when the scope is genuinely empty, never
because one batch of namespaces happened to match none.

Set `proxy.notifyEmptyScope=false` to restore the silent behaviour. It depends
on hubble-ui rendering `ui.NoPermission`, which is internal to hubble-ui.

If you need more, `--log-level=debug` separates the two underlying causes in one
line:

```console
level=DEBUG msg="request authorized" route=control-stream user=bob@example.com \
  groups="[team-a team-b]" unrestricted=false namespaces=1
```

Identity arrived and resolved — so an empty UI means the *mapping* is wrong.
Whereas:

```console
level=WARN msg="no identity on request" expecting="X-Auth-Request-Email (…)" \
  present=[] other_family_present="[X-Forwarded-Email X-Forwarded-Groups]"
```

says the authenticator is running but emitting the **other header family**, which
is the single likeliest misconfiguration (see
`--identity-header-prefix`). An empty `other_family_present` instead means no
authenticator is putting headers on the request at all.

Note debug logs name users; it is a deliberate trade for diagnosability.

**Client disconnects are classified, not hidden.** The UI holds several
long-polls open and aborts them on reload, navigation and namespace switches, so
individual disconnects say nothing and are logged at debug. What matters is the
*rate*:

```promql
# Callers abandoning requests. A sustained rise means something upstream is
# stalling them — a load balancer, the ingress, the network — not this proxy.
sum(rate(hubble_authz_requests_total{outcome="client_gone"}[5m]))

# The proxy could not vouch for a response and refused to serve it.
sum(rate(hubble_authz_requests_total{outcome="upstream_error"}[5m]))
```

Alert on those rates, not on individual log lines.

### Shutdown

The UI holds long-poll requests open, so the proxy drains on SIGTERM rather than
dropping them — otherwise every rollout surfaces as errors in the browser. Keep
`proxy.shutdownTimeout` below the pod's `terminationGracePeriodSeconds`.

---

## Known limitations

**A scope change does not update an open session's namespace picker.** The
backend sends the namespace list once per channel, roughly half a second after
the client connects, and then only when namespaces themselves change — the
recurring traffic is node status. So if you shrink a user's mapping while they
have the UI open, their picker keeps showing the old list until they reload.

This fails safe rather than open: the picker is just a list of names, and
selecting one of those stale namespaces yields nothing, because service-map
responses are filtered per message against the caller's current scope. Only the
list is stale, never the data.

**Node status is not filtered.** The first `control-stream` message is a
`Notification` carrying `GetStatusResponse`, which every authenticated user sees
in full regardless of namespace scope:

```text
nodes[]:      name, address (IP:port), cilium version, TLS server name,
              uptime, numFlows / maxFlows / seenFlows
serverStatus: relay version, flowsRate, seenFlows, connected node count
```

That is an infrastructure inventory — node hostnames, your internal addressing
and naming convention, and an exact Cilium version. It is namespace-independent,
which is why it passes through, and the UI's status header needs it. If your
tenants should not see it, this needs redacting; there is no namespace-scoped
version of the node list to substitute.

**Aggregate counters leak coarse information.** The backend aggregates the
service map *before* the proxy filters it, so `flow_amount`, `bytes_transfered`
and latency on a service or link you *are* allowed to see were computed over all
flows, including ones outside your scope. Namespace names and topology do not
leak; those totals are an inference channel. Closing it would require filtering
upstream of the aggregation, which is not possible without the caller's identity
reaching that far.

**The backend still does cluster-wide work.** Every user's session makes the
backend stream all flows from relay and aggregate the whole cluster, after which
most of it is discarded. Correctness is unaffected; cost is not.

**The `customprotocol` wire format is internal to hubble-ui.** It carries no
compatibility promise and has already been changed once (it replaced a grpc-web
`ui.UI` service). The `github.com/cilium/hubble-ui/backend` pin in `go.mod` is
therefore load-bearing — bump it in lockstep with the ui-backend image you
deploy, and let the compiler tell you what changed. Unknown routes are refused
rather than forwarded, so a mismatch fails loudly.

That loud failure only covers a **new route or a new `Event` kind** — both are
Go oneofs, so the proxy fails closed on either without needing to know about
them in advance (`filterBody`'s default case, `eventVisible`'s default case).
It does **not** cover a **new field added to an already-recognised message
type**. `eventVisible` decides keep-or-drop for the whole `*uipb.Event` by
inspecting only the fields it already knows about (a namespace name, a service
ID, ...); once kept, the message is marshalled whole, so any field a newer
proto version adds rides along unexamined. The compiler will not catch this —
an added field, unlike a renamed or removed one, does not break the build.
When bumping the pin, diff the proto for new fields on `NamespaceState`,
`ServiceState`, `ServiceLinkState`, `Flow` and `Flows` specifically, not just
for new message kinds.

**The Hubble CLI is not covered.** `hubble observe` talks to relay directly and
authenticates as a machine, so no user identity ever reaches it. Restrict relay
by NetworkPolicy if that matters.

---

## Development

```console
go build ./...
go test ./...                        # unit + golden fixtures, seconds, no Docker
go test -tags e2e -run TestE2E ./... # against the real backend, needs Docker
helm lint ./charts/hubble-authz-proxy
helm template hap ./charts/hubble-authz-proxy
```

### Layout

```text
cmd/hubble-authz-proxy/   entry point: flags, wiring, lifecycle
internal/proxy/           the proxy itself — relay, envelope, response filtering
internal/authz/           Scope + the Authorizer contract, and the static mapping
internal/authz/rbac/      the SubjectAccessReview authorizer and its RBAC watch
internal/registry/        per-channel service-ID -> namespace memory
internal/identity/        the caller, derived from the authenticator's headers
internal/metrics/         collectors and the label vocabulary they export with
internal/logging/         the process logger
```

Imports point one way, inward: `internal/metrics`, `internal/identity` and
`internal/logging` depend on nothing else here, and `internal/metrics` in
particular takes the version string and the route names as parameters rather
than reaching for them — which is what keeps every other package free to
import it.

The `e2e` suite runs the **real hubble-ui backend container** in its
`E2E_TEST_MODE`, which swaps the backend's whole clients layer for one fed by
log files — so it needs neither relay nor Kubernetes. The flows in those files
are generated by the test, so the service map the backend builds is under our
control and the assertions are deterministic.

It is the only test that exercises the filter against the backend's *real*
aggregation. Everything else builds its input with the same code under test, so
a wrong assumption about the wire format, or about how `ServiceLink` endpoints
are identified, would be invisible. `internal/proxy/testdata/` holds a real
control-stream response captured from a live cluster (node names and addresses
replaced with placeholders) to guard the decode path the same way.

Go 1.26+ is required — the `hubble-ui/backend` module sets that floor.

### Version coverage

CI runs the suite against **every hubble-ui backend the supported Cilium releases
ship**, using one binary compiled against a single set of protos — which is
exactly how it is deployed. Override the image to reproduce a matrix job locally:

```console
E2E_BACKEND_IMAGE=quay.io/cilium/hubble-ui-backend:v0.13.3 \
  go test -tags e2e -count=1 -run TestE2E ./...
```

The axis is the **hubble-ui version, not the Cilium version**. Cilium 1.18.10+,
1.19.4+, 1.20.x and 1.21.0-pre.0 all ship the same hubble-ui `v0.13.5`, so a
matrix over Cilium releases would pull identical images. Only two backends exist
across the whole window:

| hubble-ui | Shipped by |
| --- | --- |
| `v0.13.5` | Cilium 1.18.10+, 1.19.4+, 1.20.x, 1.21 (pre) — the `go.mod` pin |
| `v0.13.3` | Cilium ≤1.17.x, 1.18.0–1.18.9, 1.19.0–1.19.3 |

That mapping moves *within* a patch line — 1.19.3 shipped `v0.13.3` and 1.19.4
shipped `v0.13.5` — and no dependency bot reports it, because from this repo's
side nothing changed. So the table is a snapshot, and
[`hack/check-hubble-ui-matrix.sh`](hack/check-hubble-ui-matrix.sh) is what keeps
it true: it reads `values.yaml` from the newest patch of each supported Cilium
line and fails nightly if a version reaches users untested. Widening the matrix
stays a human decision — dropping the oldest entry means dropping support.

Renovate bumps only `defaultBackendImage` (the compile target); it is scoped away
from the matrix so a routine bump cannot collapse it onto one version and quietly
retire the back-compat coverage. `TestE2EMatrixCoversDefaultPin` fails if the two
drift apart.

Testing against a real cluster without deploying:

```console
kubectl port-forward -n kube-system deploy/hubble-ui 8091:8090
go run . --backend=http://127.0.0.1:8091 --authz-config=./mapping.example.yaml

curl -i -X POST localhost:8090/api/control-stream \
  -H 'Content-Type: application/json' \
  -H 'X-Auth-Request-Email: bob@example.com' \
  -H 'X-Auth-Request-Groups: team-payments' \
  -d '{"meta":{"route_name":"control-stream"}}'
```

> **The URL path is decorative.** The backend dispatches on `meta.route_name`
> from the request *body*; `/api/:RouteName` matches any segment and the captured
> value is never read. A request with no body — or with `routeName` instead of
> `route_name` — resolves to an empty route and returns **404**, which looks
> exactly like a missing endpoint. The envelope is plain `encoding/json` over the
> generated struct, not protojson, so the field really is snake_case.
>
> Telling the two 404s apart: the backend router writes an empty body
> (`Content-Length: 0`); an nginx or ingress 404 returns an HTML page.

Swap the identity headers between users and confirm the namespace list changes
accordingly — and that a user cannot widen scope through UI filters. Without
identity headers you get **401**, not 404.

`service-map-stream` is harder to drive by hand: its first message must carry a
`ui.GetEventsRequest` with non-empty `event_types` in `body.content` as base64
protobuf, or the backend terminates the channel with 400. Confirm the path with
`control-stream` first.

## Contributing

PR titles follow [Conventional Commits](https://www.conventionalcommits.org/);
this is enforced by CI. [Release Please](https://github.com/googleapis/release-please)
handles SemVer tagging, the changelog, and keeps `Chart.yaml` in step. Released
images are published to `ghcr.io/puzzle/hubble-authz-proxy`, signed with
cosign (keyless), and carry an SPDX SBOM attestation.

## License

Apache-2.0
