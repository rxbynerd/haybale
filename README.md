# haybale

git proxy for agentic sessions

## Documentation

- [`docs/configuration.md`](docs/configuration.md) — full config reference (TLS, identity, policy, upstreams, telemetry).
- [`docs/jwt-identity.md`](docs/jwt-identity.md) — the JWT identity contract a control plane implements so haybale accepts its tokens.
- [`docs/github-actions.md`](docs/github-actions.md) — authenticating a GitHub Actions workflow to haybale with OIDC, no PAT.
- [`docs/observability.md`](docs/observability.md) — the OpenTelemetry traces, metrics, and logs haybale emits.
- [`docs/security.md`](docs/security.md) — threat model and the security invariants the implementation enforces.
- [`docs/stirrup-integration.md`](docs/stirrup-integration.md) — deploying haybale alongside a Stirrup sandbox.
- [`docs/runbook-github-acceptance.md`](docs/runbook-github-acceptance.md) — the real-GitHub acceptance test (`just e2e-github`): a credential-less container cloning/pushing a real private repo through haybale.
- [`docs/runbook-github-actions-acceptance.md`](docs/runbook-github-actions-acceptance.md) — gated live acceptance of the GitHub Actions OIDC auth path.
