# Changelog

## [1.0.0](https://github.com/puzzle/hubble-authz-proxy/compare/v0.6.0...v1.0.0) (2026-08-21)


### ⚠ BREAKING CHANGES

* only the double-dash long-flag form is accepted now (--rbac-ttl=60s), not the single-dash form the stdlib flag package also allowed (-rbac-ttl=60s). pflag parses a single-dash multi-letter argument as a cluster of shorthand flags, so the old form now fails loudly ("unknown shorthand flag") rather than working silently. The Helm chart already renders every arg with --, so an install through the chart is unaffected; a hand-written manifest using single-dash flags needs updating. Documented in the README next to the flags table.

### Features

* evict a cached scope when RBAC changes, not when the TTL expires ([#24](https://github.com/puzzle/hubble-authz-proxy/issues/24)) ([ed35385](https://github.com/puzzle/hubble-authz-proxy/commit/ed353851a3d97621134891fbf816f8a6c5868301))
* switch the CLI from flag to cobra ([#33](https://github.com/puzzle/hubble-authz-proxy/issues/33)) ([9d960d4](https://github.com/puzzle/hubble-authz-proxy/commit/9d960d4af12a636977a9e08ba941697a34332238))

## [0.6.0](https://github.com/splattner/hubble-authz-proxy/compare/v0.5.1...v0.6.0) (2026-08-13)


### Features

* re-read the static mapping without a restart ([#22](https://github.com/splattner/hubble-authz-proxy/issues/22)) ([d45ec44](https://github.com/splattner/hubble-authz-proxy/commit/d45ec4401ae05dcc2faa8455b168aa39d7da2f3b))
* tell callers with no namespaces why the UI is empty ([#21](https://github.com/splattner/hubble-authz-proxy/issues/21)) ([fd5abeb](https://github.com/splattner/hubble-authz-proxy/commit/fd5abeb05f48e23cf390b0a00f7db240c0519159))


### Bug Fixes

* bound memory growth and refuse silently-broken scale-out ([#19](https://github.com/splattner/hubble-authz-proxy/issues/19)) ([805cd91](https://github.com/splattner/hubble-authz-proxy/commit/805cd91c186cb1c139657072e17c529160eda868))

## [0.5.1](https://github.com/splattner/hubble-authz-proxy/compare/v0.5.0...v0.5.1) (2026-08-12)


### Bug Fixes

* export client_gone and upstream_error at zero ([#9](https://github.com/splattner/hubble-authz-proxy/issues/9)) ([73b0eb8](https://github.com/splattner/hubble-authz-proxy/commit/73b0eb8d572630fe58aade8e5a9efe1b244b3aba))

## [0.5.0](https://github.com/splattner/hubble-authz-proxy/compare/v0.4.0...v0.5.0) (2026-08-12)


### Features

* structured logging with request-level diagnostics ([#7](https://github.com/splattner/hubble-authz-proxy/issues/7)) ([b8268d4](https://github.com/splattner/hubble-authz-proxy/commit/b8268d40c8ed3f3dac647a1fd95672b6777ec1f8))

## [0.4.0](https://github.com/splattner/hubble-authz-proxy/compare/v0.3.0...v0.4.0) (2026-08-12)


### Features

* **chart:** optionally run oauth2-proxy as a sidecar ([#5](https://github.com/splattner/hubble-authz-proxy/issues/5)) ([17777da](https://github.com/splattner/hubble-authz-proxy/commit/17777da0e7b0aa38c039715a383e2921cb7c9635))

## [0.3.0](https://github.com/splattner/hubble-authz-proxy/compare/v0.2.0...v0.3.0) (2026-08-11)


### Features

* **chart:** optionally deploy Hubble UI with the proxy as a sidecar ([213d7d7](https://github.com/splattner/hubble-authz-proxy/commit/213d7d7c5228df0f48fc17f56709a9be8e2e8782))

## [0.2.0](https://github.com/splattner/hubble-authz-proxy/compare/v0.1.1...v0.2.0) (2026-08-11)


### Features

* show services linked to the caller's scope ([6c27232](https://github.com/splattner/hubble-authz-proxy/commit/6c2723235d6a211503bd3669e8ecc330b307dd98))


### Bug Fixes

* make the released chart installable as-is ([2914d09](https://github.com/splattner/hubble-authz-proxy/commit/2914d09e645769cdbad32e04e33e95a04d3e09b1))

## [0.1.1](https://github.com/splattner/hubble-authz-proxy/compare/v0.1.0...v0.1.1) (2026-08-11)


### Bug Fixes

* build the image without QEMU emulation ([e8c22b7](https://github.com/splattner/hubble-authz-proxy/commit/e8c22b72a11b473607ace9bd4188b3d24eee4672))

## [0.1.0](https://github.com/splattner/hubble-authz-proxy/compare/v0.0.1...v0.1.0) (2026-08-11)


### Features

* harden rbac authorizer, drain on SIGTERM, expose metrics ([48a51c8](https://github.com/splattner/hubble-authz-proxy/commit/48a51c814f9faf68b9d8aac47a60598490e4ddd8))
* namespace-scoped authorization proxy for the Hubble UI ([cd98724](https://github.com/splattner/hubble-authz-proxy/commit/cd987244193c14aa3a212891431dce3a533e2f3f))


### Performance Improvements

* short-circuit rbac resolution for cluster-wide callers ([bbc1ccf](https://github.com/splattner/hubble-authz-proxy/commit/bbc1ccf72662e9c42c16fde73f0f5e3b8d671bdc))
