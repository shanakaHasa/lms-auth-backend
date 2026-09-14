# auth-backend

The identity provider for TeachAssist. It owns users, tenants, roles and
scopes; it hashes passwords; and it issues RS256 access tokens that the other
services verify **offline** against its JWKS endpoint.

It knows nothing about students, courses or the assistant. If a change here
needs to know what a course is, it belongs in `backend/` instead.

## Quick start

```bash
make venv        # create .venv and install with dev extras
cp .env.example .env
make up          # Postgres on :5433
make migrate     # alembic upgrade head
make api         # http://localhost:8001/docs
```

```bash
make test        # whole suite
make test-unit   # unit only, no Docker needed
make check       # lint + typecheck + test, exactly what CI runs
```

## The boundary

```
   auth-backend ──── publishes JWKS ────►  backend caches it, verifies OFFLINE
                ◄─── M2M client creds ───  backend calls back only for the
                                           revocation feed and name lookups
```

**Every normal request in the other services calls this one zero times.** That
is deliberate: auth is not in the hot path, so an outage here degrades new
logins rather than taking the application down. The cost is that revocation is
eventually consistent — see below.

## Design decisions worth knowing before you change something

**Tokens are short and verification is local.** Access tokens live 10 minutes.
Consumers verify signatures against cached JWKS without calling this service.
That means a token cannot be revoked mid-life; the compensating controls are the
short lifetime, refresh-side revocation, and the revocation feed
(`/api/v1/internal/revocations`). Revocation lag is **about 60 seconds, not
instant** — say so out loud rather than implying otherwise.

**Email is unique per tenant, not globally.** A tutor genuinely works at two
institutions. A global constraint would force email aliasing forever, so login
carries a tenant slug.

**Roles are not in the token; scopes are.** Scopes are the authorization
currency. Putting role names in a token invites consumers to make policy
decisions that belong here.

**A failed login is deliberately opaque.** Unknown user, wrong password,
disabled account and unknown tenant all return an identical 401. An unknown user
still runs a real Argon2 verify against a fixed dummy hash so the timing
matches. The real reason goes to the audit log only. `InvalidCredentials` in
`app/core/errors.py` is what enforces this.

**Refresh redemption is a single atomic UPDATE.** `SELECT` then `UPDATE` races,
and the race is indistinguishable from token theft — which means it produces
spurious mass logouts. There is a 10-second grace window so two browser tabs
refreshing at once are not mistaken for an attack.

**Argon2 concurrency is bounded.** 64 MiB per hash multiplied by unbounded
concurrent logins will OOM the container, so hashing runs in a thread behind a
semaphore.

**Configuration failures are startup crashes.** `app/core/config.py` refuses to
boot in production with a dev seed password, insecure cookies, a plaintext or
localhost issuer, or the local signer. The most dangerous failure mode for an
identity provider is starting successfully with development defaults.

## Layout

```
app/core/       config · db · logging · errors · middleware · redaction
app/crypto/     Signer protocol (LocalSigner / KmsSigner) · JWKS
app/models/     SQLAlchemy tables
app/schemas/    Pydantic request/response — the API contract
app/api/v1/     HTTP only, thin, no business logic
app/services/   All the logic. No FastAPI imports, so the CLI and tests
                drive exactly the same code the API does.
contracts/      openapi.json + token claim schema + a test fixture pack
                that lets `backend` verify tokens without running this service
```

Dependencies point one way: `api → services → models`, with `core` underneath.

## Deliberately not built

No authorization-code flow, no federation, no token exchange, no dynamic client
registration — nearly every serious identity-provider CVE lives in one of those
four, and not having them is the mitigation. No MFA yet; `amr` is already in the
token so it can be required later without a schema change.
