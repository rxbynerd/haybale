# Authenticating from GitHub Actions (no PAT)

A GitHub Actions workflow can authenticate to haybale using its **ambient
OIDC token** — the same short-lived JWT used for cloud federation. Cross-repo
Git access therefore does not require a personal access token. GitHub is the
issuer and haybale is the verifier; no long-lived client secret is needed.

This recipe assumes haybale is reachable from the runner and configured with a
GitHub Actions issuer. See the [configuration reference](configuration.md).

## 1. haybale side

Configure the GitHub Actions issuer. **The `claimBindings` are not
optional**: any workflow on github.com can mint a validly-signed token for
your audience, so the bindings are what restrict haybale to the repos and
runners you actually trust.

```yaml
identity:
  type: jwt
  issuers:
    - issuer: https://token.actions.githubusercontent.com
      jwksURL: https://token.actions.githubusercontent.com/.well-known/jwks
      algorithms: [RS256]
      audiences: [https://haybale.internal]
      claimBindings:
        repository_owner: rxbynerd          # only your org's workflows
        runner_environment: github-hosted   # only GitHub-hosted runners
      identityTemplate: "gha:{repository}"
```

> GitHub Enterprise Server uses a **different** issuer
> (`https://<host>/_services/token`) and JWKS URL — add it as a second
> issuer entry rather than editing this one.

Policy then matches the rendered identity (`gha:{repository}`):

```yaml
rules:
  - identities: ["gha:rxbynerd/*"]
    repos: ["github.com/rxbynerd/*"]
    permissions: [read, write]
```

### Reusable-workflow caveat

When a job runs through a **reusable workflow**, `job_workflow_ref` names
the *called* workflow's repo, which may differ from `repository`. If you
rely on reusable workflows, bind `job_workflow_ref` too so a token cannot
be minted from an unexpected workflow definition.

## 2. Workflow side

Grant the job `id-token: write`, request a token **for haybale's
audience** immediately before the `git` operation, and feed it as the
Basic-auth password.

```yaml
jobs:
  clone-through-haybale:
    runs-on: ubuntu-latest
    permissions:
      id-token: write        # required to request an OIDC token
      contents: read
    steps:
      - name: Fetch an OIDC token for haybale
        id: oidc
        uses: actions/github-script@v7
        with:
          script: |
            const token = await core.getIDToken('https://haybale.internal')
            core.setSecret(token)
            core.setOutput('token', token)

      - name: Clone a private repo through haybale
        env:
          HAYBALE_TOKEN: ${{ steps.oidc.outputs.token }}
        run: |
          git -c http.extraheader="Authorization: Bearer ${HAYBALE_TOKEN}" \
            clone https://haybale.internal/github.com/rxbynerd/other-repo.git
```

The audience passed to `getIDToken(...)` **must** be one of the issuer's
configured `audiences`; a token minted for a different (or default)
audience is rejected.

### The 5-minute TTL

A GitHub Actions OIDC token lives ~5 minutes. haybale authenticates at the
**start** of a request, so a single long clone or push that outlives its
token is fine — there is no mid-stream re-auth. But a workflow doing
**several** `git` operations should request a **fresh** token immediately
before each one rather than reusing a token minted at the top of the job,
which may have expired by the time a later step runs.

## 3. Verify

The [GitHub Actions acceptance runbook](runbook-github-actions-acceptance.md)
walks through a live clone/push test and the evidence to capture.
