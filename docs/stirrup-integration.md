# Stirrup integration

haybale exists to close a gap Stirrup's own documentation names
explicitly: Stirrup sandboxes are credential-free by construction — the
only environment variables the container executor injects are
`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`
(`harness/internal/executor/container.go`) — so cloning a *private*
repository today means either an unauthenticated `preRun` `git clone`
(which simply fails against a private repo) or smuggling a real git
credential onto the sandbox's disk, which Stirrup's own security model
rejects: `ValidateRunConfig` structurally rejects a `secret://` reference
in a hook `command`, and Stirrup's `docs/security.md` says plainly that
"Clone/deploy credentials belong in control-plane runtime bindings … never
in `RunConfig`" — a binding that, at the time of writing, doesn't exist.
haybale is that binding, deployed as its own component rather than a
Stirrup code change.

This integration is **documentation only** — nothing here requires a
change to Stirrup itself. It uses two mechanisms Stirrup already has
(the Ring 2 egress allowlist, and `hooks.preRun`) plus one Git already
has (env-sourced config via `GIT_CONFIG_COUNT`).

> **Authentication is now JWT-based.** haybale no longer mints its own
> static tokens; it verifies a signed **JWT** that a control plane issued
> to the run, against that issuer's JWKS (`docs/jwt-identity.md`). The
> sandbox wiring below is unchanged in shape — the credential is still fed
> as the Basic-auth password — but the credential is now a control-plane
> JWT, not a `haybale token new` string.
>
> Stirrup does not yet have a control plane that can issue such JWTs (the
> `stirrup` binary is a gRPC client with no signing/JWKS infrastructure),
> so this document describes the **target** integration. Until an external
> control plane can mint per-run JWTs per the contract, the concrete,
> deployable-today issuer is **GitHub Actions OIDC**
> (`docs/github-actions.md`); Stirrup-side issuance is tracked separately
> and is out of scope for haybale.

## Deployment

Run haybale as its own Deployment/Service, in the same namespace as (and
reachable the same way as) Stirrup's `stirrup-egress-proxy` Deployment
(`app=stirrup-egress-proxy`, see `examples/k8s/egress-proxy/` in the
Stirrup repo) — i.e. inside the cluster boundary the sandbox's egress
proxy itself lives behind, not exposed publicly. Configure TLS
(`docs/configuration.md`) unless haybale's listener is genuinely
reachable only from that trusted, cluster-internal network.

A sandbox's outbound HTTP/HTTPS traffic (git included — `git`'s smart-HTTP
transport honours `HTTP_PROXY`/`HTTPS_PROXY` like any well-behaved HTTP
client) is always routed through `stirrup-egress-proxy` when
`network.mode: allowlist`, and that proxy forwards a request only if its
destination FQDN (and port, if non-443 — see below) matches an entry in
the run's `network.allowlist`
(`docs/safety-rings.md`'s Ring 2 section in the Stirrup repo). So:

- **Add haybale's address to `network.allowlist`** — e.g.
  `haybale.internal:8466` (the FQDN matching rule defaults to port 443
  when unsuffixed, so haybale's actual listen port must be included
  explicitly unless it's fronted by something on 443).
- **Leave `github.com` off the allowlist.** Every git remote URL the
  sandbox uses is rewritten (see "Sandbox wiring" below) to point at
  haybale instead of `github.com` directly, so nothing inside the
  sandbox needs `github.com` in the allowlist at all — and *not* adding
  it means haybale is the only path to GitHub content this run has,
  rather than an optional one a misconfigured tool could route around.

**Cooperative-enforcement caveat, inherited from Ring 2 as-is:** the
egress allowlist (and so this whole integration) depends on the
in-container client honouring `HTTP_PROXY`/`HTTPS_PROXY`. Stirrup's own
docs are explicit that a misbehaving client — raw TCP, a custom DNS
resolver, an env-stripped subprocess — can still reach the container's
bridge gateway directly, because "the current implementation enforces
fail-closed via the proxy env vars only." This integration doesn't
change that posture one way or the other: it rides on whatever
enforcement Ring 2 provides today, no more and no less. A well-behaved
`git clone`/`git push` is fully covered; a sandbox process that
deliberately dials out on a raw socket is a Ring 2 gap this integration
inherits, not one haybale introduces.

## Provisioning (operator, per run)

For each run that needs access, the control plane (not the agent, and not
anything inside the sandbox) does two things ahead of time:

1. Issue a JWT for that run, per `docs/jwt-identity.md`: signed with the
   control plane's key, `iss` equal to haybale's configured issuer, `aud`
   equal to haybale's configured audience, and `sub: run-<RunID>` (so an
   `identityTemplate: "{sub}"` renders the identity as `run-<RunID>`).
   `<RunID>` is Stirrup's own `RunConfig.RunID` — using it keeps haybale's
   audit log (`identity=run-<RunID>` on every proxied request and security
   event) correlated with Stirrup's own per-run tracing. The JWT is handed
   to whatever provisions the sandbox's environment (see below); haybale
   holds only the issuer's public keys, never the signing key.

   Optionally, the control plane can narrow a single run below the YAML
   policy by including a `repoScopeClaim` array on the token
   (`docs/jwt-identity.md`) — per-run blast-radius reduction that a static
   token could not express.

2. Add a `policy.yaml` rule scoping `run-<RunID>` to exactly the
   repo(s) and verb(s) that run needs — nothing broader:

   ```yaml
   rules:
     - identities: ["run-<RunID>"]
       repos: ["github.com/acme/widgets"]
       permissions: [read]
   ```

   Use `haybale policy check --id run-<RunID> --repo <host/owner/repo>
   --verb <read|write>` to confirm the rule does what's intended before
   the run starts (`docs/configuration.md`).

## Sandbox wiring — pure env, nothing on disk

The sandbox needs two things: haybale's token, and git configuration
that (a) redirects a `https://github.com/...` remote to haybale and (b)
supplies the token as a credential on that redirected request. Both are
expressible purely as environment variables — no file ever needs to be
written to the sandbox's disk, which matters because anything a hook
*does* write to disk stays readable by every later `run_command` for the
rest of the run.

```
HAYBALE_TOKEN=<the run's JWT, issued by the control plane per docs/jwt-identity.md>

GIT_CONFIG_COUNT=2
GIT_CONFIG_KEY_0=url.http://haybale.internal:8466/github.com/.insteadOf
GIT_CONFIG_VALUE_0=https://github.com/
GIT_CONFIG_KEY_1=credential.http://haybale.internal:8466/.helper
GIT_CONFIG_VALUE_1=!f() { echo username=x-access-token; echo "password=$HAYBALE_TOKEN"; }; f
```

- `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` is Git's own
  mechanism (since Git 2.31) for supplying arbitrary config entries via
  environment variables, with no `~/.gitconfig` or `.git/config` write
  required.
- `url.<base>.insteadOf` rewrites any remote URL starting with
  `https://github.com/` to `http://haybale.internal:8466/github.com/`
  instead — haybale's host-in-path scheme
  (`docs/configuration.md`'s "Upstreams" section) means this one rewrite
  rule is enough for every repo under `github.com`, not one rule per
  repo.
- `credential.<url-prefix>.helper` scopes the credential helper to
  exactly haybale's URL (the *rewritten* URL Git actually requests,
  which is what credential-helper matching is keyed on) — not a blanket
  `credential.helper` that would also fire for unrelated remotes. The
  helper itself is an inline shell one-liner (the `!` prefix runs it
  through the shell) that echoes the token straight from
  `$HAYBALE_TOKEN`; it never touches disk, and its output goes to Git
  over a pipe, never into the run's transcript.

With this in place, Stirrup's existing `hooks.preRun` needs no changes
at all:

```json
{
  "hooks": {
    "preRun": [
      { "name": "clone", "command": "git clone https://github.com/acme/widgets.git .", "timeoutSeconds": 60 }
    ]
  }
}
```

`git` resolves `https://github.com/acme/widgets.git` through
`insteadOf` to `http://haybale.internal:8466/github.com/acme/widgets.git`,
authenticates that request with the credential helper's output, and the
request goes out through the sandbox's proxy env exactly like any other
outbound HTTPS call — the hook author never needs to know haybale is
involved at all. It Just Works.

*How `HAYBALE_TOKEN`/`GIT_CONFIG_*` actually land in the sandbox's
environment is an operator/deployment concern outside haybale's own
scope* — e.g. a Kubernetes `Sandbox` custom resource's pod-template
overlay, or (v0.2, see below) a first-class RunConfig field. This
document specifies what those variables must contain, not how the
surrounding infrastructure delivers them.

## v0.2 futures

Two follow-ups are explicitly out of scope for this integration as
written, tracked for later:

- **Auto-provisioning.** Rather than an operator running `haybale token
  new`/editing `policy.yaml` by hand per run, a future `identity.Authenticator`
  implementation (behind the same `Authenticator` seam
  `StaticTokenAuthenticator` implements today — see
  `internal/identity/identity.go`) could derive and verify a token as
  `HMAC(shared_key, RunID)`, letting Stirrup and haybale agree on a
  per-run credential with no manual provisioning step and no token ever
  persisted anywhere.
- **Cedar policy backend.** haybale's `policy.Engine` interface
  (`internal/policy/policy.go`) is deliberately narrow so a Cedar-backed
  implementation can replace `GlobEngine` without touching
  `internal/proxy` — unifying haybale's authorization model with
  Stirrup's own Cedar-based Ring 3 (`docs/safety-rings.md`), including
  Stirrup's `User::"<runId>"` principal shape, instead of running two
  separate policy languages side by side.
