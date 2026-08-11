# Changelog

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
