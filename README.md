# pack-auth

`pack-auth` is a wallet-authorized API usage-pack service. A pack grants a fixed number of calls, belongs to one buyer wallet, and keeps its authoritative balance in PostgreSQL.

## Core flow

```text
Merchant registers a service and pack catalog
  -> buyer completes payment outside pack-auth
  -> merchant issues a pack to the buyer wallet
  -> buyer signs once with Phantom to activate a session
  -> later calls use the secure session cookie
  -> each successful call atomically deducts one use
```

For a 100-use pack, session activation leaves 100 uses available. The first protected call reduces the balance to 99. Different buyers and different packs always have independent balances.

## Main features

- Merchant-signed service registration, update, retirement, issuance, and revocation
- Public pack catalog and service information
- RS256-signed pack tokens and JWKS publication
- One-time Phantom wallet activation by the pack payer
- `HttpOnly`, `SameSite=Strict` session cookie
- Exact-Origin checking for session-protected endpoints
- PostgreSQL row locking and atomic per-use deduction
- Idempotency keys that prevent retries from charging twice
- Resource scopes, expiry, exhaustion, logout, and revocation checks
- Authoritative balance introspection and consumption ledger

Payment settlement is external. The merchant should call the issue flow only after its payment system confirms payment.

## Authentication model

| Operation | Required proof |
|---|---|
| Issue a pack | Merchant wallet signature |
| Activate a session | Pack Bearer token + payer Phantom signature |
| Consume or inspect | Session cookie + allowed Origin |
| Revoke a pack | Merchant wallet signature |

The pack token cannot call `/consume` directly. It is used only to activate a session with the matching payer wallet.

## Key endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service and database health |
| GET | `/.well-known/jwks.json` | RS256 public keys |
| GET | `/v1/services/{wallet}/challenge` | Wallet-signing challenge |
| POST | `/v1/services/{wallet}/register` | Register a service and catalog |
| POST | `/v1/services/{wallet}/update` | Update a service |
| POST | `/v1/packs/issue` | Issue a paid pack |
| POST | `/v1/packs/session` | Activate a secure session |
| POST | `/v1/packs/consume` | Deduct one use atomically |
| POST | `/v1/packs/introspect` | Read the current balance |
| POST | `/v1/packs/logout` | Revoke the current session |
| POST | `/v1/packs/revoke` | Revoke a pack |
| GET | `/v1/marketplace/packs` | List public pack products |

See [`public/openapi.json`](public/openapi.json) for the API description.

## Database

For a new database:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/init.sql
```

For an existing installation that needs secure sessions:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_secure_sessions.sql
```

## Configuration

Use `env.example` as the environment template. The most important values are:

- `DATABASE_URL`
- `PACK_AUTH_HMAC_SECRET`
- `PACK_AUTH_RSA_PRIVATE_KEY_PEM`
- `PACK_AUTH_KEY_ID`
- `PACK_AUTH_ISS`
- `PACK_AUTH_ALLOWED_ORIGIN`
- `PACK_AUTH_SESSION_TTL_SECONDS`
- `PACK_AUTH_COOKIE_SECURE`

For local HTTP development, use the exact frontend origin and set `PACK_AUTH_COOKIE_SECURE=false`. For every production HTTPS deployment, set `PACK_AUTH_COOKIE_SECURE=true`.

Frontend calls to `/session`, `/consume`, `/introspect`, and `/logout` must use `credentials: "include"`. Serve the frontend over HTTP or HTTPS instead of opening it with `file://`.

## Verify

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The backend never stores a wallet private key and never connects directly to Phantom. Phantom signs in the browser; the backend only verifies the signed message.
