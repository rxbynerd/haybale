# Stirrup integration

This guide describes how to route Git smart-HTTP traffic from a Stirrup
sandbox through haybale without placing an upstream Git credential in the
sandbox.

The integration uses:

- Stirrup's HTTP/HTTPS proxy and egress allowlist;
- a JWT issued for the run by a trusted control plane;
- Git's environment-based configuration; and
- a haybale policy identity derived from the run token.

The surrounding control plane must implement the [JWT issuer
contract](jwt-identity.md). If runs originate in GitHub Actions, the
[GitHub Actions OIDC integration](github-actions.md) can supply the token
instead.

## Deployment model

Deploy haybale where both the Stirrup egress proxy and the configured Git hosts
are reachable. A cluster-internal service is the usual topology. Configure
listener TLS unless the client-to-haybale network is private and trusted; see
the [security model](security.md#tls).

For a run using an egress allowlist:

1. Add haybale's service address and port, for example
   `haybale.internal:8466`.
2. Do not add `github.com` when all GitHub access must go through haybale.
3. Ensure the sandbox's Git process retains `HTTP_PROXY`, `HTTPS_PROXY`, and
   `NO_PROXY` as required by the Stirrup deployment.

This control inherits the enforcement properties of Stirrup's network mode.
Git honors the proxy variables, but software that bypasses the configured HTTP
proxy must be constrained by the sandbox network layer if direct egress is a
concern.

## Per-run provisioning

Before starting a run, the control plane should:

1. issue a short-lived JWT for the run;
2. make the token available to the sandbox as `HAYBALE_TOKEN`; and
3. ensure haybale policy grants the derived identity only the repositories and
   operations required by the run.

A typical issuer configuration derives the identity directly from `sub`:

```yaml
identity:
  type: jwt
  issuers:
    - issuer: https://control-plane.example.internal
      jwksURL: https://control-plane.example.internal/.well-known/jwks.json
      algorithms: [ES256]
      audiences: [https://haybale.internal]
      typ: at+jwt
      identityTemplate: "{sub}"
      repoScopeClaim: haybale.dev/repos
```

For Stirrup run `01JABC...`, the control plane can issue `sub:
run-01JABC...`. Policy then uses the same identity:

```yaml
rules:
  - identities: ["run-01JABC..."]
    repos: ["github.com/acme/widgets"]
    permissions: [read]
```

Use a `repoScopeClaim` in the token when the control plane knows the exact
repository set for a run. The token scope narrows the YAML policy and cannot
grant access by itself.

Validate a policy decision before starting the run:

```sh
haybale policy check --config haybale.yaml \
  --id run-01JABC... \
  --repo github.com/acme/widgets \
  --verb read
```

## Sandbox Git configuration

Git 2.31 and later can receive configuration entirely through environment
variables. The following values rewrite GitHub HTTPS URLs to haybale and supply
the run JWT only to haybale's URL:

```sh
HAYBALE_TOKEN=<short-lived run JWT>

GIT_CONFIG_COUNT=2
GIT_CONFIG_KEY_0=url.http://haybale.internal:8466/github.com/.insteadOf
GIT_CONFIG_VALUE_0=https://github.com/
GIT_CONFIG_KEY_1=credential.http://haybale.internal:8466/.helper
GIT_CONFIG_VALUE_1='!f() { echo username=x-access-token; echo "password=$HAYBALE_TOKEN"; }; f'
```

For a TLS listener, use `https://haybale.internal/...` in both keys.

`url.<base>.insteadOf` rewrites:

```text
https://github.com/acme/widgets.git
```

to:

```text
http://haybale.internal:8466/github.com/acme/widgets.git
```

The credential helper is scoped to haybale's rewritten URL. It does not run for
unrelated remotes. Both the rewrite and helper remain in process environment;
no `.gitconfig`, `.netrc`, or credential file is required.

With these variables present, a normal pre-run hook needs no proxy-specific
command:

```json
{
  "hooks": {
    "preRun": [
      {
        "name": "clone",
        "command": "git clone https://github.com/acme/widgets.git .",
        "timeoutSeconds": 60
      }
    ]
  }
}
```

## Secret-handling requirements

- Treat `HAYBALE_TOKEN` as a bearer credential until it expires.
- Do not include its value in `RunConfig`, hook commands, transcripts, or
  persistent files.
- Avoid shell tracing (`set -x`) around credential-helper setup.
- Issue a token with a lifetime appropriate to the run and repository scope as
  narrow as practical.
- Remove the token from any long-lived parent process after sandbox launch when
  the deployment mechanism permits it.

The sandbox token works only against haybale. haybale replaces it with an
upstream credential after authentication and authorization. The upstream
credential remains inside the haybale process.

## Verification

For an integration smoke test:

1. run `haybale policy check` for the run identity and target repository;
2. clone through the original GitHub URL with the environment rewrite active;
3. verify haybale logs the expected identity, repository, and `read` operation;
4. attempt a repository outside policy and confirm Git receives `404`; and
5. inspect the sandbox for `.netrc`, `.git-credentials`, or an upstream token.

For a full GitHub App round trip, use the [live GitHub acceptance
runbook](runbook-github-acceptance.md).
