# Runbook: GitHub Actions OIDC live acceptance (gated)

**Status: gated — manual, requires a network-reachable haybale and a
scratch repo. Do not run without owner go-ahead.**

This runbook proves the end-to-end goal of issue #2: a GitHub Actions
workflow, holding no PAT, authenticates to haybale with its ambient OIDC
token and performs a credential-less cross-repo clone/push. It is the live
counterpart to the local `just e2e-github` acceptance
(`docs/runbook-github-acceptance.md`) and mirrors that runbook's evidence
-capture style.

Unlike the local acceptance (which stands up a throwaway ES256 issuer via
`scripts/mint-e2e-jwt`), this one uses the **real** GitHub Actions issuer,
so it additionally exercises live JWKS fetch/refresh against
`https://token.actions.githubusercontent.com`.

## Preconditions

- A haybale deployment **reachable from a GitHub Actions runner**. Two
  shapes work; record which you used:
  - haybale exposed at a public (or GitHub-reachable) HTTPS address, hit by
    a github-hosted runner; or
  - haybale on a private network, hit by a **self-hosted** runner adjacent
    to it (in which case `runner_environment` is `self-hosted`, not
    `github-hosted` — adjust the `claimBindings` accordingly).
- A GitHub App installed on the scratch repos, configured as haybale's
  upstream `github-app` credential (as in the v0.1 acceptance).
- Two scratch repos under your org: one to clone, one to push to (or one
  repo exercised for both verbs).

## haybale config

```yaml
identity:
  type: jwt
  issuers:
    - issuer: https://token.actions.githubusercontent.com
      jwksURL: https://token.actions.githubusercontent.com/.well-known/jwks
      algorithms: [RS256]
      audiences: [https://haybale.internal]
      claimBindings:
        repository_owner: <your-org>
        runner_environment: github-hosted   # or self-hosted, per above
      identityTemplate: "gha:{repository}"
policy:
  path: policy.yaml
```

```yaml
# policy.yaml — grant only the scratch repos, only the verbs under test
rules:
  - identities: ["gha:<your-org>/<clone-repo>"]
    repos: ["github.com/<your-org>/<clone-repo>"]
    permissions: [read]
  - identities: ["gha:<your-org>/<push-repo>"]
    repos: ["github.com/<your-org>/<push-repo>"]
    permissions: [read, write]
```

haybale must start cleanly — the initial JWKS fetch from GitHub is
fail-fast, so a successful start already proves outbound reachability to
the Actions JWKS endpoint.

## Workflow

In the scratch repo, add the workflow from `docs/github-actions.md`
(`id-token: write`, `core.getIDToken('https://haybale.internal')`, token
fed as the git Basic-auth password against haybale's URL). Exercise both a
clone of the read-only repo and a push to the writable one, requesting a
**fresh** token immediately before each git operation (5-minute TTL).

## Evidence to capture

Mirroring the v0.1 `e2e-github` runbook:

1. **Workflow run**: the Actions log showing the clone and push succeeding
   with no PAT in the environment (only the OIDC-minted token).
2. **haybale logs**: for each request, a `proxied request` line carrying
   `identity=gha:<org>/<repo>`, `issuer=https://token.actions.githubusercontent.com`,
   the verb, and `status=200`; and the `token_minted` upstream events —
   never a raw token in any line.
3. **Negative check**: a workflow in a repo **outside** the `claimBindings`
   (or a token requested for the wrong audience) is rejected `401`,
   proving the bindings are load-bearing.
4. **Scope check (optional)**: if the deployment uses `repoScopeClaim`, a
   token scoped to one repo is denied `404` on another the policy would
   otherwise allow.

## Cleanup

Remove the scratch workflow and any scratch repos/branches created.
Rotate the GitHub App key if it was exposed anywhere during setup.
