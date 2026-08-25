# Runbook: GitHub Actions OIDC live acceptance

This manual test verifies that a GitHub Actions workflow can authenticate to
haybale with an OIDC token and perform private repository operations without a
personal access token.

Run it only with owner approval against dedicated scratch repositories. The
workflow must be able to reach the haybale listener.

## Preconditions

- A haybale deployment reachable from the selected runner:
  - use HTTPS and a GitHub-hosted runner for a publicly reachable endpoint; or
  - use a self-hosted runner adjacent to a private haybale deployment.
- A GitHub App installed on the scratch repositories and configured as
  haybale's `github-app` upstream credential.
- One or two private scratch repositories for clone and push operations.
- A haybale audience value chosen for this deployment, such as
  `https://haybale.internal`.

## Configure haybale

Configure GitHub's OIDC issuer and bind it to the organization and runner class
under test:

```yaml
identity:
  type: jwt
  issuers:
    - issuer: https://token.actions.githubusercontent.com
      jwksURL: https://token.actions.githubusercontent.com/.well-known/jwks
      algorithms: [RS256]
      audiences: [https://haybale.internal]
      claimBindings:
        repository_owner: YOUR_ORG
        runner_environment: github-hosted # use self-hosted when applicable
      identityTemplate: "gha:{repository}"

policy:
  path: /etc/haybale/policy.yaml
```

Grant only the workflow repositories and operations being tested:

```yaml
rules:
  - identities: ["gha:YOUR_ORG/WORKFLOW_REPO"]
    repos: ["github.com/YOUR_ORG/CLONE_REPO"]
    permissions: [read]
  - identities: ["gha:YOUR_ORG/WORKFLOW_REPO"]
    repos: ["github.com/YOUR_ORG/PUSH_REPO"]
    permissions: [read, write]
```

Start haybale and confirm `GET /healthz` returns `200`. Startup performs the
initial GitHub JWKS fetch, so a clean start also confirms that the deployment
can reach the issuer.

## Run the workflow

Add a temporary workflow to `WORKFLOW_REPO` based on the
[GitHub Actions integration](github-actions.md). It must:

1. grant `id-token: write`;
2. request a token for haybale's configured audience immediately before each
   Git operation;
3. mark the token as a secret;
4. pass it to Git as an `Authorization: Bearer` header; and
5. avoid any PAT, deploy key, or GitHub App token in workflow secrets.

Exercise a clone from `CLONE_REPO` and a push to `PUSH_REPO`. Request a new OIDC
token before each operation because GitHub OIDC tokens are short-lived.

## Positive evidence

Capture:

1. the workflow run URL and job log showing successful clone and push;
2. haybale `proxied request` records with the expected
   `identity=gha:YOUR_ORG/WORKFLOW_REPO`, verified issuer, repository, verb, and
   `status=200`;
3. `token_minted` events for required GitHub App scopes, with no token value;
   and
4. the pushed commit SHA confirmed independently through GitHub's UI or API.

Do not copy OIDC tokens, authorization headers, private keys, or installation
tokens into the evidence.

## Negative checks

Perform at least one of these checks:

- request an OIDC token for the wrong audience and confirm haybale returns
  `401`;
- run the workflow from a repository outside `claimBindings` and confirm a
  `401`; or
- request a repository outside policy and confirm a `404`.

If `repoScopeClaim` is configured, also test a token whose repository scope
excludes a repository otherwise allowed by policy; haybale should return `404`.

## Cleanup

- Remove the temporary workflow and test branches.
- Delete or reset scratch repositories according to their retention policy.
- Remove temporary policy grants.
- Remove any public route created solely for the test.
- Rotate the GitHub App key if its handling during the test did not meet normal
  secret-management requirements.
