# hubble-authz-proxy

[![PR Quality](https://github.com/splattner/hubble-authz-proxy/actions/workflows/pr-quality.yml/badge.svg)](https://github.com/splattner/hubble-authz-proxy/actions/workflows/pr-quality.yml)
[![Release Please](https://github.com/splattner/hubble-authz-proxy/actions/workflows/release-please.yml/badge.svg)](https://github.com/splattner/hubble-authz-proxy/actions/workflows/release-please.yml)

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
| `control-stream` | `Notification` | Passed through — relay/k8s connection state is cluster-wide |
| `service-map-stream` | `Flow`, `Flows` | Dropped unless an endpoint is in scope |
| `service-map-stream` | `ServiceState` | Dropped unless `service.namespace` is in scope |
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

Point 3 deserves care: in Cilium's default install the backend is a *sidecar* in
the hubble-ui pod listening on `127.0.0.1:8090`, with no Service of its own. It
is still reachable at `podIP:8090` from anywhere in the cluster. Restrict ingress
to the hubble-ui pod accordingly.

Everything in the proxy fails closed. An unknown route, an unrecognised event
kind, an unparseable payload, or a missing scope all produce a 502 with no body
rather than a pass-through.

---

## Install

```console
helm repo add hubble-authz-proxy https://splattner.github.io/hubble-authz-proxy
helm repo update
helm install hubble-authz-proxy hubble-authz-proxy/hubble-authz-proxy \
  --namespace kube-system \
  --values values.yaml
```

Install it in the **same namespace as hubble-ui** — the chart creates a Service
that selects the hubble-ui pod to expose the backend sidecar, and a Service can
only select pods in its own namespace.

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

The proxy reads this once at startup. `authz.checksumAnnotation` (on by default)
rolls the Deployment when the ConfigMap changes.

**`rbac`** — asks the API server, per namespace, whether the caller may `list
pods` there, via `SubjectAccessReview`. Tracks real `kubectl` access with no
mapping to maintain.

A resolution costs one review per namespace, so three things guard it:

- results are cached per identity for `authz.cacheTTL` (the cache is bounded and
  swept, since its keys come from caller-supplied headers);
- **singleflight** collapses concurrent misses for the same identity — a cold
  cache under load issues one sweep, not one per in-flight request;
- the sweep runs 16 reviews in parallel, so latency is roughly
  `namespaces / 16` round trips rather than `namespaces`.

If any single review fails, the whole resolution fails. A partial answer would
look like a smaller namespace set — an under-show that then gets cached — so it
errors instead, and failures are never cached.

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
| `--rbac-ttl` | `60s` | Cache TTL for a resolved namespace set |
| `--channel-ttl` | `10m` | How long per-channel service-map state survives an idle client |
| `--require-both-endpoints` | `false` | Strict cross-namespace policy |
| `--metrics-listen` | `:9090` | Serves `/metrics` and `/healthz`; empty disables it |
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
| `hubble_authz_tracked_channels` | gauge | — |

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

### Shutdown

The UI holds long-poll requests open, so the proxy drains on SIGTERM rather than
dropping them — otherwise every rollout surfaces as errors in the browser. Keep
`proxy.shutdownTimeout` below the pod's `terminationGracePeriodSeconds`.

---

## Known limitations

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

**The Hubble CLI is not covered.** `hubble observe` talks to relay directly and
authenticates as a machine, so no user identity ever reaches it. Restrict relay
by NetworkPolicy if that matters.

---

## Development

```console
go build ./...
go test ./...
helm lint ./charts/hubble-authz-proxy
helm template hap ./charts/hubble-authz-proxy
```

Go 1.26+ is required — the `hubble-ui/backend` module sets that floor.

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
images are published to `ghcr.io/splattner/hubble-authz-proxy`, signed with
cosign (keyless), and carry an SPDX SBOM attestation.

## License

Apache-2.0
