# pack-auth

`pack-auth` is a usage-pack entitlement service modeled after `subscription-auth2`. A seller settles payment in its own x402/pr402 route, then uses a wallet-signed challenge to issue a finite-use RS256 Bearer token.

The important difference from a subscription is that remaining uses are mutable. The JWT identifies the pack and carries immutable scope; Postgres is authoritative for `used_uses`, revocation, expiry, and the consumption ledger.

## Core flow

1. Merchant registers a service and its `pack_bundles` catalog.
2. Buyer pays the seller. Payment is outside this service.
3. Merchant signs an `issue` challenge containing `service_id`, `payer`, `pack_id`, `total_uses`, `validity_seconds`, and `resources_json`.
4. `POST /v1/packs/issue` returns an RS256 Bearer token.
5. For every protected request, the seller calls `POST /v1/packs/consume` with that Bearer token, the target resource, and a stable `Idempotency-Key` for the business request.
6. The server locks the pack row and atomically writes the consumption record plus increments `used_uses`. Repeating the same key returns the original result without charging twice.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | health and DB status |
| GET | `/.well-known/jwks.json` | JWT verification keys |
| GET | `/v1/services/{wallet}/challenge` | wallet challenge for `register`, `update`, `retire`, `issue`, `revoke`, or `list` |
| POST | `/v1/services/{wallet}/register` | service and pack catalog registration |
| POST | `/v1/services/{wallet}/update` | allowlist/catalog update |
| POST | `/v1/services/{wallet}/retire` | service retirement |
| POST | `/v1/services/{wallet}/packs` | merchant pack list |
| POST | `/v1/packs/issue` | issue a paid pack |
| POST | `/v1/packs/consume` | consume one use atomically |
| POST | `/v1/packs/introspect` | authoritative remaining balance |
| POST | `/v1/packs/revoke` | merchant revocation |
| GET | `/v1/revocations` | revocation delta feed |
| GET | `/v1/marketplace/packs` | public catalog |
| GET | `/v1/info/{service_id}` | registration status |

`consume` requires both `Authorization: Bearer <token>` and `Idempotency-Key: <stable-request-id>`. Its JSON body is `{ "resource": "/api/v1/data" }`.

## Catalog shape

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

## Deploy

Apply `migrations/init.sql` manually, set the variables in `env.example`, and deploy the Vercel Rust function. This service never accepts payment and never stores a buyer private key.

## Verify

```bash
cargo fmt --all -- --check
cargo clippy --bin auth_api -- -D warnings
cargo test
```
