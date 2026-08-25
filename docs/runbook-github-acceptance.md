# Runbook: live GitHub App acceptance

This manual acceptance test starts haybale locally, then runs a container that
clones and pushes a private GitHub repository through it. The container receives
a haybale JWT but no GitHub credential. haybale uses a real GitHub App to mint
the upstream installation tokens.

Run the test only against a dedicated scratch repository. It creates and pushes
a commit. The test is not part of CI because it requires a GitHub App private
key, a private repository, GitHub CLI credentials, and a container runtime.

## Prerequisites

- Go and `just`
- Docker or Podman
- [GitHub CLI](https://cli.github.com/) authenticated as an account that can
  inspect the scratch repository
- a private scratch repository with a `main` branch and at least one commit
- a GitHub App installed on that repository

The GitHub App needs only these repository permissions:

- **Contents:** Read and write
- **Metadata:** Read-only (automatically required by GitHub)

Webhooks and a callback URL are not needed.

## Create or configure the GitHub App

1. Open **Settings → Developer settings → GitHub Apps → New GitHub App**.
2. Choose a unique name and a valid homepage URL.
3. Disable webhooks and leave the callback URL empty.
4. Grant **Contents: Read and write** and no optional permission beyond it.
5. Restrict installation to the dedicated scratch repository where possible.
6. Record the App ID.
7. Generate a private key and store it outside every source repository.
8. Restrict the key file to its owner:

   ```sh
   chmod 600 /secure/path/github-app.pem
   ```

haybale rejects group- or world-accessible private keys.

Create and seed a scratch repository if necessary:

```sh
gh repo create OWNER/haybale-e2e --private \
  --description "haybale acceptance test scratch repository"

git clone git@github.com:OWNER/haybale-e2e.git
cd haybale-e2e
printf '# haybale acceptance scratch\n' > README.md
git add README.md
git commit -m 'Initialize acceptance repository'
git push -u origin main
```

## Run the test

Build haybale, then provide the App ID, repository, and key path explicitly:

```sh
just build

HAYBALE_APP_ID=123456 \
HAYBALE_APP_KEY_PATH=/secure/path/github-app.pem \
HAYBALE_E2E_REPO=OWNER/haybale-e2e \
HAYBALE_CONTAINER_RUNTIME=podman \
just e2e-github
```

Use `HAYBALE_CONTAINER_RUNTIME=docker` for Docker.

Optional controls:

| Variable | Purpose |
|---|---|
| `HAYBALE_BIN` | haybale binary path; defaults to `./haybale` |
| `HAYBALE_E2E_PORT` | host listener port; defaults to a PID-derived port |
| `HAYBALE_E2E_SCRATCH` | generated config, token, and log directory; defaults to `.e2e-github.$PID` |

The script removes its scratch directory on success, failure, or interruption.
The `.gitignore` pattern also excludes it as defense in depth.

## What the script verifies

The script:

1. creates a temporary ES256 signing key, a public JWKS file, and a short-lived
   run JWT;
2. writes a policy that grants that run identity read and write access to only
   `HAYBALE_E2E_REPO`;
3. starts haybale with the local JWKS and the real GitHub App configuration;
4. starts an `alpine/git` container with only `HAYBALE_URL` and
   `HAYBALE_TOKEN` supplied by the host;
5. configures Git through `GIT_CONFIG_*` environment variables, without writing
   credentials or Git configuration to disk;
6. clones the private repository, commits a marker, and pushes it through
   haybale;
7. checks the container filesystem and environment for GitHub token and private
   key patterns;
8. confirms the pushed SHA through an independent `gh api` request; and
9. shuts down the container and haybale, escalating to a forced stop if graceful
   teardown does not complete promptly.

A successful run ends with:

```text
CREDENTIAL_CHECK: PASS
...
e2e-github: ALL CHECKS PASSED
```

It also prints a security-log excerpt. Expect one or more `proxied request`
records and `token_minted` events. No JWT, GitHub installation token, or private
key should appear in the output.

## Credential-isolation checks

The container verifies that:

- `.netrc` and `.git-credentials` do not exist;
- no newly created or modified file contains a known GitHub token prefix or PEM
  private-key header; and
- no environment value contains those upstream credential patterns.

The run JWT is intentionally present as `HAYBALE_TOKEN`. It authenticates only
to haybale and is limited by the generated policy. The check is specifically
for credentials that work directly against GitHub.

## Container-to-host networking

The script uses `host.containers.internal` so the container can reach the
haybale listener on the host. Podman and Docker Desktop commonly provide this
name. If it does not resolve in your Docker installation, configure a host
mapping supported by that runtime, for example:

```sh
docker run --add-host host.containers.internal:host-gateway ...
```

The test listener uses plain HTTP because the container and local haybale
process communicate only across the developer machine's container bridge. This
does not relax the TLS guidance for deployed environments.

## Troubleshooting

- **haybale rejects the key permissions:** run `chmod 600` on the App key and
  verify that the mounted or resolved file preserves that mode.
- **installation lookup returns 404:** confirm the App is installed on the exact
  owner/repository named by `HAYBALE_E2E_REPO`.
- **token mint returns 403 or 422:** confirm the App has Contents read/write and
  that `HAYBALE_APP_ID` matches the private key.
- **container cannot reach haybale:** verify the runtime's host-gateway DNS name
  and set `HAYBALE_E2E_PORT` to an available port.
- **independent confirmation fails:** run `gh auth status` and verify the active
  account can read the private repository.

Because the test pushes a real commit, inspect or reset the scratch repository
after testing according to your retention policy.
