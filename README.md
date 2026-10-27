# ipso-server

Source-available ipso control plane: bitemporal decision registry, API, web app and PR checks.

> Status: skeleton. The control plane lands in a later change.

One Go modular monolith ships the registry API, the web SPA, the entitlement contract, the Helm chart and the Compose bundle, plus a separate Python worker for LLM extraction. The binary is `ipso-server`, started with `--role`.

Module rule: `go.mod` may require `ipso`. Enterprise features register from `ipso-ee` through the `ee` build tag. Each release converts to Apache-2.0 two years after publication. Enterprise builds use the same version number: EE vX.Y.Z matches server vX.Y.Z.

## License

Functional Source License, Version 1.1, Apache 2.0 future license (FSL-1.1-ALv2). See [LICENSE](LICENSE).

Copyright 2026 Luca Bertelli.

## Contributing

Follow the contributor terms in [ipsofacto-io/.github](https://github.com/ipsofacto-io/.github/blob/main/CONTRIBUTING.md).
