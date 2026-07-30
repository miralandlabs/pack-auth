# pack-auth

`pack-auth` is a finite-usage entitlement service modeled after `subscription-auth2`.
Instead of granting access for a period of time, it grants a fixed number of uses, such as 10, 100, or 1,000 API calls.

The service binds every pack to its own buyer wallet and database record. Two buyers who each purchase a 10-use pack therefore each start with 10 independent uses.

## What this project does

`pack-auth` provides the backend for:

- registering a merchant service and its pack catalog;
- issuing a paid usage pack to a specific buyer wallet;
- returning an RS256-signed pack token;
- requiring the buyer's Phantom wallet signature once to activate a browser session;
- allowing later calls without another wallet signature;
- checking the session and pack state on every protected call;
- atomically deducting exactly one use;
- preventing duplicate charges when a request is retried;
- reporting authoritative remaining uses;
- expiring, revoking, and logging out pack sessions;
- exposing public catalogs, service information, JWKS, and revocation data.

This service does **not** process a blockchain payment by itself. Payment settlement happens in the merchant's payment route. After payment succeeds, the merchant authorizes `pack-auth` to issue the pack.

## The complete flow in plain language

```text
Merchant setup
    |
    | Phantom signs a registration challenge
    v
Register service and pack catalog
    |
    v
Buyer pays through the merchant's external payment flow
    |
    | Merchant confirms payment and signs an issue challenge
    v
Issue pack token for the buyer wallet
    |
    | Buyer signs once with the matching Phantom wallet
    v
Create secure session and set an HttpOnly cookie
    |
    | No more Phantom signatures for normal usage
    v
Consume API call -> validate session -> validate pack -> deduct one use
    |
    v
Return the authoritative remaining balance
```

For a 100-use pack:

```text
Purchase and issue:       100 remaining
Phantom activation:      100 remaining (activation does not deduct)
First protected call:     99 remaining
Second protected call:    98 remaining
...
Last protected call:       0 remaining
Next call:              rejected with PACK_EXHAUSTED
```

## The three credentials and why they exist

| Item | Simple meaning | Where it is used |
|---|---|---|
| Pack token | Proof that the merchant issued this pack | Sent once to `/v1/packs/session` |
| Phantom signature | Proof that the person activating the pack controls the buyer wallet | Required once during session activation |
| Session cookie | Short-lived browser access credential | Sent automatically on consume, introspect, and logout |

The pack token alone cannot consume uses. To activate it, an attacker would also need a valid, fresh Phantom signature from the pack's payer wallet. After activation, the raw session secret is placed in an `HttpOnly` cookie and only its SHA-256 hash is stored in PostgreSQL.

## Roles

### Merchant

The merchant owns a Solana wallet, registers the service, defines pack products, confirms external payment, issues packs, and can revoke packs.

### Buyer

The buyer pays for a pack and owns the Phantom wallet recorded as the pack's `payer`. The buyer signs once to activate a session.

### Frontend

The frontend connects to Phantom, requests challenges, asks Phantom to sign the exact challenge message, and calls the backend with `credentials: "include"` so the browser can receive and send the secure cookie.

### pack-auth backend

The backend verifies challenges and wallet signatures, issues JWTs, creates sessions, checks permissions, performs atomic database deductions, and returns the remaining balance.

### PostgreSQL

PostgreSQL is the source of truth. The JWT describes the pack, but the database decides whether it is active and how many uses remain.

## Detailed business flow

### 1. Register a service

The merchant requests a `register` challenge, signs the returned message with Phantom, and submits the signature with:

- `service_id`;
- `service_url`;
- the allowed resource list;
- the pack catalog.

The challenge binds these values cryptographically. Changing a catalog value after signing makes verification fail.

### 2. Complete payment outside pack-auth

The buyer pays through the merchant's own payment integration. `pack-auth` does not verify or transfer USDC directly.

### 3. Issue a pack

After payment is confirmed, the merchant signs an `issue` challenge containing the buyer wallet, pack ID, total uses, validity period, and resource scope. `/v1/packs/issue` then:

1. verifies the merchant wallet signature;
2. verifies that the merchant owns the service;
3. checks the pack against the registered catalog;
4. creates an independent pack row identified by a unique `jti`;
5. returns an RS256 pack token.

The token contains immutable claims. Mutable values such as `used_uses`, revocation, and remaining balance live in PostgreSQL.

### 4. Activate the pack once with Phantom

The buyer requests a `session` challenge bound to both `service_id` and the pack's `jti`. The buyer signs that exact message with Phantom and sends it to `/v1/packs/session` together with:

```http
Authorization: Bearer <pack-token>
Origin: <PACK_AUTH_ALLOWED_ORIGIN>
```

The backend verifies:

- the JWT signature, issuer, expiry, and key ID;
- that the JWT matches the database pack;
- that the pack exists, is active, and is not expired;
- that the signing wallet equals the pack's `payer`;
- that the challenge is fresh, unused, and bound to this pack.

If everything matches, the backend creates a random session secret, stores only its hash, and returns a `pack_session` cookie with `HttpOnly` and `SameSite=Strict`. In HTTPS deployments it also uses `Secure`.

Creating the session does not consume one use.

### 5. Consume one use without another Phantom signature

The frontend calls `/v1/packs/consume` with the session cookie, the target resource, and a stable `Idempotency-Key`:

```js
const response = await fetch(`${apiBase}/v1/packs/consume`, {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "Idempotency-Key": crypto.randomUUID(),
  },
  body: JSON.stringify({ resource: "/api/v1/data" }),
});
```

For each call, the backend:

1. requires the exact configured `Origin`;
2. hashes the session cookie and finds the database session;
3. checks that the session is active and not expired;
4. checks that the session wallet equals the pack payer;
5. checks that the requested resource is inside the pack scope;
6. locks the pack row in a database transaction;
7. checks revocation, expiry, and remaining uses;
8. writes a consumption ledger record;
9. increments `used_uses` by exactly one;
10. commits both changes together and returns `remaining_uses`.

The database row lock prevents concurrent requests from overspending the same pack.

### 6. Retry safely with idempotency

Every logical business request must keep the same `Idempotency-Key` when retried. If a network timeout causes the frontend to send the same request again, the backend returns the original result with `replayed: true` and does not deduct a second use.

Reusing the same key for a different resource returns `409 Conflict`.

### 7. Read balance and session state

`POST /v1/packs/introspect` uses the session cookie and returns the authoritative pack state, including:

- total uses;
- used uses;
- remaining uses;
- expiry time;
- revocation state;
- whether the pack is currently active.

### 8. Logout, expire, or revoke

- `/v1/packs/logout` revokes the current session and clears its cookie.
- A session automatically stops working when its session expiry is reached.
- A pack automatically stops working when its pack expiry is reached.
- The merchant can revoke a pack through `/v1/packs/revoke`.
- A revoked or exhausted pack cannot be consumed even if the browser still has a cookie.

## User isolation

Each issued pack has a unique `jti` and its own `total_uses` and `used_uses` values.

```text
Wallet A -> Pack jti-A -> total 10 -> used 2 -> remaining 8
Wallet B -> Pack jti-B -> total 10 -> used 0 -> remaining 10
```

Wallet B never starts from Wallet A's remaining balance. A session is also tied to one pack and one payer wallet.

## API summary

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| GET | `/health` | Public | Check service and database health |
| GET | `/.well-known/jwks.json` | Public | Publish RS256 verification keys |
| GET | `/openapi.json` | Public | Return the OpenAPI document |
| GET | `/v1/services/{wallet}/challenge` | Public | Create a one-time wallet-signing challenge |
| POST | `/v1/services/{wallet}/register` | Merchant signature | Register a service and catalog |
| POST | `/v1/services/{wallet}/update` | Merchant signature | Update allowlist and catalog |
| POST | `/v1/services/{wallet}/retire` | Merchant signature | Retire a service |
| POST | `/v1/services/{wallet}/packs` | Merchant signature | List issued packs |
| POST | `/v1/packs/issue` | Merchant signature | Issue a pack after payment settlement |
| POST | `/v1/packs/session` | Pack token + buyer signature | Activate a secure browser session |
| POST | `/v1/packs/consume` | Session cookie + Origin + idempotency key | Atomically consume one use |
| POST | `/v1/packs/introspect` | Session cookie + Origin | Read authoritative balance |
| POST | `/v1/packs/logout` | Session cookie + Origin | Revoke the current session |
| POST | `/v1/packs/revoke` | Merchant signature | Revoke an issued pack |
| GET | `/v1/revocations` | Public | Read the incremental revocation feed |
| GET | `/v1/marketplace/packs` | Public | List public pack products |
| GET | `/v1/marketplace/packs/{service_id}` | Public | Read one public catalog entry |
| GET | `/v1/info/{service_id}` | Public | Read service registration status |

Challenge actions are `register`, `update`, `retire`, `issue`, `revoke`, `list`, and `session`. Challenges expire after 10 minutes and their nonces can only be consumed once.

## Catalog example

```json
{
  "display": {
    "name": "Example API packs",
    "category": "developer-tools",
    "tags": ["api"]
  },
  "packs": [
    {
      "id": "starter-10",
      "name": "10 requests",
      "total_uses": 10,
      "validity_seconds": 2592000,
      "price_usdc": 2.5
    }
  ]
}
```

The price is catalog metadata. Payment enforcement belongs to the external merchant payment flow.

## Database model

| Table | Purpose |
|---|---|
| `pack_auth_services` | Merchant services, allowlists, public metadata, and pack catalogs |
| `pack_auth_packs` | One independent record per issued pack and its usage counter |
| `pack_auth_consumptions` | Immutable per-use ledger and idempotency records |
| `pack_auth_sessions` | Hashed browser sessions tied to a pack and payer wallet |
| `pack_auth_nonces` | Short-lived, one-time wallet challenge nonces |
| `pack_auth_signing_keys` | Public keys used for JWT verification and key rotation |

Apply the canonical schema to a new database with:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/init.sql
```

For a database that already has the original schema, apply the secure-session migration:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_secure_sessions.sql
```

## Project structure

```text
pack-auth/
├── migrations/       PostgreSQL schema and upgrade migrations
├── public/           OpenAPI document
├── src/
│   ├── api/          HTTP handlers and resource/catalog logic
│   ├── bin/          Vercel runtime entry point and route table
│   ├── db.rs         PostgreSQL queries and atomic consumption transaction
│   ├── challenge_auth.rs  Challenge creation and Phantom signature verification
│   ├── jwt.rs        RS256 pack token issuance and verification
│   ├── config.rs     Environment configuration
│   ├── http_util.rs  JSON, cookie, CORS, and request helpers
│   ├── state.rs      Shared application state
│   └── error.rs      API error mapping
├── Cargo.toml        Rust package and dependencies
├── Cargo.lock        Locked dependency versions
├── env.example       Required environment variable template
└── vercel.json       Vercel function and rewrite configuration
```

## Environment variables

Copy `env.example` to your local environment configuration and replace all placeholders.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `PACK_AUTH_HMAC_SECRET` | Secret of at least 32 bytes used to bind challenges |
| `PACK_AUTH_RSA_PRIVATE_KEY_PEM` | RS256 private key used to sign pack tokens |
| `PACK_AUTH_KEY_ID` | Current JWT signing key ID |
| `PACK_AUTH_ISS` | Expected JWT issuer |
| `PACK_AUTH_ALLOWED_ORIGIN` | Exact frontend origin allowed to use session endpoints |
| `PACK_AUTH_SESSION_TTL_SECONDS` | Session lifetime, clamped to 5 minutes through 30 days |
| `PACK_AUTH_COOKIE_SECURE` | Adds the `Secure` cookie flag; must be `true` on HTTPS |
| `PACK_AUTH_MAX_NONCES_PER_WALLET` | Maximum pending challenges per wallet |
| `PACK_AUTH_MAX_USES` | Maximum allowed uses in one pack |
| `PACK_AUTH_MAX_VALIDITY_SECONDS` | Maximum pack lifetime |
| `PACK_AUTH_REVOCATION_WINDOW_DAYS` | Maximum revocation feed lookback |
| `PACK_AUTH_SSL_NO_VERIFY` | Disables PostgreSQL certificate verification; never enable in production |

Local HTTP example:

```env
PACK_AUTH_ALLOWED_ORIGIN=http://localhost:3001
PACK_AUTH_COOKIE_SECURE=false
```

Production HTTPS example:

```env
PACK_AUTH_ALLOWED_ORIGIN=https://app.example.com
PACK_AUTH_COOKIE_SECURE=true
```

Do not commit a real `.env`, database password, HMAC secret, or RSA private key.

## Frontend requirements

The frontend and API must use the exact origin configured by `PACK_AUTH_ALLOWED_ORIGIN`. Calls to session-protected endpoints must include cookies:

```js
fetch(`${apiBase}/v1/packs/introspect`, {
  method: "POST",
  credentials: "include",
});
```

Serve the frontend through HTTP or HTTPS. Opening it as `file://...` is not a valid end-to-end setup for Phantom detection, Origin checks, CORS, and secure cookies.

The backend never connects directly to Phantom. Phantom runs in the browser; the frontend requests a signature, and the backend verifies the resulting signature.

## Security properties

- Ed25519 Phantom signatures prove control of a Solana wallet.
- HMAC-bound challenges prevent clients from changing signed business fields.
- Ten-minute, single-use nonces prevent replaying wallet signatures.
- The payer wallet must match the wallet that activates the pack.
- The pack token cannot directly call `/consume`.
- Session secrets use 32 bytes of secure randomness.
- Only the SHA-256 session hash is stored in PostgreSQL.
- `HttpOnly` prevents frontend JavaScript from reading the cookie.
- `SameSite=Strict` and exact-Origin checks reduce cross-site request forgery risk.
- `Secure` protects the cookie in production HTTPS deployments.
- Database row locks and transactions prevent concurrent overspending.
- Idempotency keys prevent retries from charging twice.
- Resource scopes prevent a pack from being used outside its allowlist.
- Pack expiry, session expiry, exhaustion, and merchant revocation are checked against PostgreSQL.

These controls do not replace normal frontend security. Production frontends should also use HTTPS, a restrictive Content Security Policy, careful dependency management, rate limiting, monitoring, and XSS prevention.

## Expected error cases

| Status | Meaning |
|---|---|
| `400` | Invalid JSON, fields, resource, or idempotency key |
| `401` | Invalid token/signature or missing, expired, or revoked session |
| `403` | Origin or resource is not allowed |
| `402` | The pack has no remaining uses |
| `404` | The requested service or pack does not exist |
| `409` | Duplicate registration or idempotency-key conflict |
| `500` | Backend configuration or internal failure |
| `503` | Required infrastructure is unavailable |

## Verification

Run the Rust checks before publishing changes:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

A complete end-to-end verification should additionally prove:

1. a real Phantom wallet can sign and activate its own pack;
2. a different wallet cannot activate that pack;
3. activation leaves the balance unchanged;
4. one consume call deducts exactly one use;
5. retrying the same idempotency key does not deduct again;
6. concurrent requests never take the balance below zero;
7. an expired, revoked, exhausted, or logged-out session cannot consume;
8. Wallet A and Wallet B maintain independent balances;
9. requests from a different Origin are rejected;
10. production cookies contain `HttpOnly`, `SameSite=Strict`, and `Secure`.

## Current system boundary

The implemented backend covers service registration, pack issuance, one-time wallet activation, secure session use, atomic deduction, balance inspection, logout, expiry, and revocation.

The remaining external integrations are:

- the merchant's real payment verification;
- the production frontend that calls Phantom;
- operational rate limiting, alerting, and scheduled cleanup;
- full PostgreSQL concurrency and browser end-to-end tests.
