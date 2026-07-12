# The haybale JWT identity contract

haybale authenticates a caller by verifying a signed JWT that a **control
plane** issued to it. haybale is a pure verifier: it mints nothing, holds
no signing key, and trusts an issuer only through that issuer's published
public keys (a JWKS). This document specifies what a control plane must
produce so haybale accepts its tokens. It is written for someone
implementing issuance — it does not require reading haybale's source.

The shape follows [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)
(JWT access tokens) and the hardening rules of
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) (JWT BCP). GitHub
Actions OIDC is a conformant issuer out of the box; see
`docs/github-actions.md`.

## Transport

A caller presents its token to haybale as the **HTTP Basic-auth password**
(the username is ignored — this is what `git` itself sends) or as an
`Authorization: Bearer <token>` header. The token is the caller's only
credential; haybale strips it before forwarding upstream and injects the
upstream's own credential in its place.

## Header

| Field | Requirement |
|-------|-------------|
| `alg` | An **asymmetric** signature algorithm the issuer is configured for in haybale — `ES256` (recommended) or `RS256`. HMAC algorithms and `none` are **rejected unconditionally**; haybale never accepts a symmetric or unsigned token. |
| `kid` | **Required.** Names the key in the JWKS that signed this token, so haybale can select it and so key rotation works. |
| `typ` | `at+jwt` is **recommended** (RFC 9068 explicit typing). haybale only enforces `typ` for an issuer configured with a required value; GitHub's own `JWT` is accepted where no specific `typ` is required. |

## Claims

| Claim | Requirement |
|-------|-------------|
| `iss`  | **Required.** Must equal, exactly, the `issuer` string the operator configured for you in haybale. It selects your trust material; a token is only ever verified against the keys of the issuer its `iss` names. |
| `sub`  | **Required.** A stable identifier for the workload, e.g. `run-<RunID>`. Available to haybale's `identityTemplate` as `{sub}`. |
| `aud`  | **Required.** Must contain (at least) the audience the operator configured for you (e.g. `https://haybale.internal`). A token with no `aud`, or an `aud` that does not intersect the configured set, is rejected. |
| `exp`  | **Required.** Unix expiry. haybale imposes no maximum, but a short lifetime (≤ 15 minutes recommended) bounds the damage of a leaked token. Tokens without `exp` are rejected. |
| `iat`  | Recommended. Rejected if in the future beyond leeway. |
| `nbf`  | Optional. Honored if present. |
| `jti`  | **Recommended.** A unique token ID; haybale logs it (never the token) on successful authentication, so a security event can be correlated to a specific issuance without exposing the credential. |

### Identity claims

haybale renders the **authenticated identity** — the ID your policy rules
match against — from verified claims via the issuer's `identityTemplate`.
For a control-plane run identity, `identityTemplate: "{sub}"` with
`sub: run-<RunID>` is the natural choice. For structured issuers (GitHub
Actions), prefer specific claims (`{repository}`) over parsing `sub`.

Every claim an `identityTemplate` references must be present and
string-typed, or authentication fails.

### `claimBindings`

An operator may pin your issuer to specific claim values (e.g.
`repository_owner: rxbynerd`). Any claim they bind must be present on your
token with a matching value. This is mandatory for open issuers (see
`docs/security.md`); for a dedicated control plane it is optional.

### Optional: `repoScopeClaim` (per-token narrowing)

You may narrow a single token's authorization below the operator's YAML
policy by including a claim — whose name the operator configures as
`repoScopeClaim` — carrying an array of `{host}/{owner}/{repo}` glob
strings:

```json
"haybale.dev/repos": ["github.com/rxbynerd/haybale", "github.com/rxbynerd/stirrup"]
```

haybale computes `effective = policy ∩ repoScope`: a repo must be allowed
by the YAML policy **and** matched by the scope. This lets a control plane
shrink a run's blast radius per-run without ever letting a token
self-authorize a repo the policy does not already permit. Semantics:

- **Absent** claim → no narrowing; policy alone decides.
- **Non-empty** list → only repos matching both policy and a scope glob.
- **Empty** list → every repo denied (the token asserted "no repos").

A glob follows Go's `path.Match` (`*` does not cross `/`), so each entry
names all three segments: `github.com/rxbynerd/*`, never `rxbynerd/*`.

## Key distribution (JWKS)

Publish your public keys as a JWKS document. haybale reaches it one of two
ways, per issuer:

- **`jwksURL`** — an `https` URL haybale fetches and refreshes in the
  background, honoring `Cache-Control`. This is the norm for a networked
  control plane.
- **`jwksFile`** — a static JWKS on haybale's disk, for airgapped
  deployments; rotation means editing the file and restarting.

Rotate with standard **overlap rotation**: publish the new key alongside
the old before signing with it, let haybale pick it up (it refetches on an
unseen `kid`, rate-limited), then retire the old key once no live token
still uses it. Each key needs a distinct `kid`.

A note on trust: your JWKS endpoint is, by construction, able to mint any
identity for your issuer — a spoofed or compromised JWKS is equivalent to
a signing-key compromise. haybale requires `https` (except loopback) and
keeps each issuer's trust material separate; the operator's `claimBindings`
bound the blast radius. See `docs/security.md`.

## Worked example (control-plane token)

Header:

```json
{ "alg": "ES256", "kid": "cp-2026-07", "typ": "at+jwt" }
```

Payload:

```json
{
  "iss": "https://control-plane.example.internal",
  "sub": "run-9f2c1a",
  "aud": "https://haybale.internal",
  "iat": 1752300000,
  "exp": 1752300900,
  "jti": "b1946ac9-2f0e-4f1b-9d2b-7c3f5a1e0d84",
  "haybale.dev/repos": ["github.com/rxbynerd/haybale"]
}
```

With the matching issuer config from `docs/configuration.md`, haybale
authenticates this as identity `run-9f2c1a`, scoped to
`github.com/rxbynerd/haybale`.
