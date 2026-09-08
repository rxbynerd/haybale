# haybale

haybale is an authenticating reverse proxy for Git smart HTTP. It lets
workloads clone and push private repositories without giving those workloads a
credential that works directly against the upstream Git host.

A client authenticates to haybale with a signed JWT. haybale verifies the token,
applies a default-deny repository policy, obtains an upstream credential, and
streams the Git request without buffering pack data. The client token is never
forwarded upstream, and the upstream credential is never returned to the
client.

## Features

- JWT authentication with per-issuer JWKS, audience, algorithm, claim-binding,
  and identity-template controls
- ordered, default-deny authorization rules for repository read and write access
- per-request, least-privilege GitHub App installation tokens, or static
  credentials for other Git hosts
- streaming Git smart-HTTP proxying with no pack-size limit
- TLS, graceful draining, structured security logs, and optional OpenTelemetry
  traces, metrics, and logs

haybale supports Git smart HTTP only. It does not support SSH, Git's dumb HTTP
protocol, ref-level authorization, or pack-content inspection.

## Build and run

haybale requires Go 1.26 or later.

```sh
go build -o haybale ./cmd/haybale
./haybale serve --config haybale.yaml
```

With [just](https://github.com/casey/just), the common development commands are:

```sh
just build
just test
just test-race
just lint
just image-build
```

The container image uses `/etc/haybale/haybale.yaml` by default:

```sh
HAYBALE_CONTAINER_RUNTIME=docker just image-build
docker run --rm -p 8466:8466 \
  -v "$PWD/haybale.yaml:/etc/haybale/haybale.yaml:ro" \
  -v "$PWD/policy.yaml:/etc/haybale/policy.yaml:ro" \
  haybale:dev
```

Mount any configured certificates, JWKS files, or GitHub App keys as read-only
files as well. Private key files must have owner-only permissions (`0600` or
stricter) and must be readable by the image's `nonroot` user (UID/GID 65532).

## Published image

Every push to `main` publishes a `linux/amd64` and `linux/arm64` image to
GitHub Packages, tagged `latest` and `sha-<commit>`:

```sh
podman pull ghcr.io/rxbynerd/haybale:latest
```

Pin a deployment to a commit rather than `latest`:

```sh
podman pull ghcr.io/rxbynerd/haybale:sha-<full-commit-sha>
```

Each published digest carries a signed build provenance attestation,
verifiable with the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/rxbynerd/haybale:latest --repo rxbynerd/haybale
```

## Request flow

Clients address a repository with haybale's host-in-path URL form:

```text
https://haybale.example/github.com/acme/widgets.git
```

For each smart-HTTP request, haybale:

1. parses the upstream host, owner, repository, and Git read/write operation;
2. verifies the caller's JWT and derives its policy identity;
3. authorizes the identity against `policy.yaml` and any token repository scope;
4. replaces the caller's authorization header with the configured upstream
   credential; and
5. streams the request and response between the client and upstream.

See the [configuration reference](docs/configuration.md) for complete examples.

## CLI

```text
haybale serve [--config haybale.yaml]
haybale policy check --config haybale.yaml --id ID --repo HOST/OWNER/REPO --verb read|write
haybale version
```

`GET /healthz` returns `200` while the server is ready and `503` while it is
draining.

## Documentation

- [Configuration reference](docs/configuration.md)
- [JWT issuer contract](docs/jwt-identity.md)
- [GitHub Actions OIDC integration](docs/github-actions.md)
- [OpenTelemetry signals](docs/observability.md)
- [Security model](docs/security.md)
- [Stirrup integration](docs/stirrup-integration.md)
- [Live GitHub App acceptance runbook](docs/runbook-github-acceptance.md)
- [GitHub Actions OIDC acceptance runbook](docs/runbook-github-actions-acceptance.md)

## License

Licensed under the [Apache License 2.0](LICENSE).
