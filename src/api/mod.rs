mod marketplace;
mod resources;

use {
    chrono::{DateTime, Utc},
    serde::Deserialize,
    serde_json::{json, Value},
    std::sync::Arc,
    uuid::Uuid,
    vercel_runtime::{Body, Response},
};

use crate::{
    challenge_auth::{self, Action, BoundFields, ChallengeBuildParams, ParsedChallenge},
    db::{ChallengeNonceOutcome, ConsumeOutcome, InsertServiceParams, PackRow, ServiceRow},
    error::{into_vercel_response, Error},
    http_util::{cors_options, json_response, parse_wallet_path},
    jwt,
    pack_bundles::{extract_catalog_index, find_pack, validate_pack_bundles},
    service_id::validate_service_id,
    state::AppState,
};

pub use marketplace::{handle_marketplace_detail, handle_marketplace_list};
use resources::{resource_allowed, resources_subset_of_allowlist};

const CHALLENGE_TTL_SECONDS: u64 = 600;

#[derive(Deserialize)]
pub struct SignedBody {
    pub message: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct RegisterBody {
    #[serde(flatten)]
    pub signed: SignedBody,
    pub service_id: String,
    pub service_url: String,
    pub resources_allowlist: Vec<String>,
    pub pack_bundles: Option<Value>,
}

#[derive(Deserialize)]
pub struct UpdateBody {
    #[serde(flatten)]
    pub signed: SignedBody,
    pub service_id: String,
    pub resources_allowlist: Vec<String>,
    pub pack_bundles: Option<Value>,
}

#[derive(Deserialize)]
pub struct ConsumeBody {
    pub resource: String,
}

#[derive(Deserialize)]
pub struct ListPacksBody {
    #[serde(flatten)]
    pub signed: SignedBody,
    pub service_id: Option<String>,
    pub before: Option<String>,
}

pub async fn handle_health(state: Arc<AppState>) -> Response<Body> {
    let mut value = json!({
        "status": "ok",
        "service": "pack-auth",
        "db": if state.db.is_some() { "configured" } else { "missing" }
    });
    if let Some(db) = &state.db {
        let db_ping = match db.ping().await {
            Ok(()) => String::from("ok"),
            Err(error) => format!("error: {error}"),
        };
        value["db_ping"] = json!(db_ping);
    }
    json_response(200, &value)
}

pub async fn handle_jwks(state: Arc<AppState>) -> Response<Body> {
    json_response(200, &state.jwks_document().await)
}

pub async fn handle_challenge(state: Arc<AppState>, wallet: String, query: &str) -> Response<Body> {
    let result = async {
        let map = crate::http_util::parse_query_map(query);
        let action = Action::parse(
            map.get("action")
                .ok_or_else(|| Error::BadRequest("action is required".into()))?,
        )
        .map_err(Error::BadRequest)?;
        let fields = BoundFields {
            service_id: map.get("service_id").cloned(),
            service_url: map.get("service_url").cloned(),
            resources_allowlist_json: map
                .get("resources_allowlist_json")
                .or_else(|| map.get("resources_allowlist"))
                .cloned(),
            pack_bundles_json: map.get("pack_bundles_json").cloned(),
            payer: map.get("payer").cloned(),
            pack_id: map.get("pack_id").cloned(),
            total_uses: map.get("total_uses").cloned(),
            validity_seconds: map.get("validity_seconds").cloned(),
            resources_json: map
                .get("resources_json")
                .or_else(|| map.get("resources"))
                .cloned(),
            jti: map.get("jti").cloned(),
        };
        let (message, expires_unix) = challenge_auth::build_challenge_message(
            &state.config.hmac_secret,
            &wallet,
            CHALLENGE_TTL_SECONDS,
            ChallengeBuildParams { action, fields },
        )
        .map_err(Error::BadRequest)?;
        let nonce = message
            .lines()
            .find_map(|line| line.strip_prefix("nonce: "))
            .ok_or_else(|| Error::Internal("nonce missing".into()))?;
        let expires = DateTime::from_timestamp(expires_unix as i64, 0)
            .ok_or_else(|| Error::Internal("invalid challenge expiry".into()))?;
        let max_nonces = std::env::var("PACK_AUTH_MAX_NONCES_PER_WALLET")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(10)
            .max(1);
        let db = state.require_db()?;
        if db
            .insert_challenge_nonce(&wallet, nonce, expires, max_nonces)
            .await?
            == ChallengeNonceOutcome::RateLimited
        {
            return Err(Error::BadRequest(format!(
                "too many pending challenges (max {max_nonces})"
            )));
        }
        if expires_unix % 100 == 0 {
            tokio::spawn(async move {
                if let Err(error) = db.cleanup_expired_nonces().await {
                    tracing::warn!(%error, "nonce cleanup failed");
                }
            });
        }
        Ok(json!({ "message": message, "expires_unix": expires_unix }))
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_register(
    state: Arc<AppState>,
    wallet: String,
    body_text: String,
) -> Response<Body> {
    let result = async {
        let body: RegisterBody = parse_body(&body_text)?;
        validate_service_id(&body.service_id)?;
        validate_pack_bundles(body.pack_bundles.as_ref(), state.config.max_pack_uses)?;
        let parsed = verify_and_consume(&state, &wallet, &body.signed, Action::Register).await?;
        ensure_bound(&parsed.fields.service_id, &body.service_id, "service_id")?;
        ensure_bound(&parsed.fields.service_url, &body.service_url, "service_url")?;
        let allowlist_json = challenge_auth::minify_json_array(&body.resources_allowlist).map_err(Error::BadRequest)?;
        ensure_bound(&parsed.fields.resources_allowlist_json, &allowlist_json, "resources_allowlist")?;
        let bundles_json = serde_json::to_string(&body.pack_bundles).map_err(|e| Error::BadRequest(e.to_string()))?;
        ensure_bound(&parsed.fields.pack_bundles_json, &bundles_json, "pack_bundles")?;
        let db = state.require_db()?;
        if db.get_service(&body.service_id).await?.is_some() { return Err(Error::Conflict("service_id already registered".into())); }
        let allowlist: Value = serde_json::from_str(&allowlist_json).map_err(|e| Error::BadRequest(e.to_string()))?;
        let (category, tags) = extract_catalog_index(body.pack_bundles.as_ref());
        db.insert_service(InsertServiceParams { service_id: &body.service_id, merchant_wallet: &wallet, service_url: &body.service_url, resources_allowlist: &allowlist, pack_bundles: body.pack_bundles.as_ref(), category: category.as_deref(), tags: &tags }).await?;
        Ok(json!({ "success": true, "service_id": body.service_id, "merchant_wallet": wallet, "service_url": body.service_url }))
    }.await;
    into_vercel_response(result)
}

pub async fn handle_update(
    state: Arc<AppState>,
    wallet: String,
    body_text: String,
) -> Response<Body> {
    let result = async {
        let body: UpdateBody = parse_body(&body_text)?;
        validate_service_id(&body.service_id)?;
        if body.pack_bundles.is_some() {
            validate_pack_bundles(body.pack_bundles.as_ref(), state.config.max_pack_uses)?;
        }
        let parsed = verify_and_consume(&state, &wallet, &body.signed, Action::Update).await?;
        ensure_bound(&parsed.fields.service_id, &body.service_id, "service_id")?;
        let allowlist_json = challenge_auth::minify_json_array(&body.resources_allowlist)
            .map_err(Error::BadRequest)?;
        ensure_bound(
            &parsed.fields.resources_allowlist_json,
            &allowlist_json,
            "resources_allowlist",
        )?;
        let bundles_json = serde_json::to_string(&body.pack_bundles)
            .map_err(|e| Error::BadRequest(e.to_string()))?;
        ensure_bound(
            &parsed.fields.pack_bundles_json,
            &bundles_json,
            "pack_bundles",
        )?;
        let service = load_active_service(&state, &body.service_id).await?;
        if service.merchant_wallet != wallet {
            return Err(Error::Unauthorized("not service merchant".into()));
        }
        let allowlist: Value =
            serde_json::from_str(&allowlist_json).map_err(|e| Error::BadRequest(e.to_string()))?;
        let (category, tags) = extract_catalog_index(body.pack_bundles.as_ref());
        let updated = state
            .require_db()?
            .update_service(
                &body.service_id,
                &wallet,
                &allowlist,
                body.pack_bundles.as_ref(),
                category.as_deref(),
                body.pack_bundles.as_ref().map(|_| &tags),
            )
            .await?;
        if !updated {
            return Err(Error::NotFound("service not found or retired".into()));
        }
        Ok(json!({ "success": true, "service_id": body.service_id }))
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_retire(
    state: Arc<AppState>,
    wallet: String,
    body_text: String,
) -> Response<Body> {
    let result = async {
        let signed: SignedBody = parse_body(&body_text)?;
        let parsed = verify_and_consume(&state, &wallet, &signed, Action::Retire).await?;
        let service_id = parsed
            .fields
            .service_id
            .ok_or_else(|| Error::BadRequest("service_id required".into()))?;
        if !state
            .require_db()?
            .retire_service(&service_id, &wallet)
            .await?
        {
            return Err(Error::NotFound("service not found".into()));
        }
        Ok(json!({ "success": true, "service_id": service_id, "status": "retired" }))
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_issue(state: Arc<AppState>, body_text: String) -> Response<Body> {
    let result = async {
        let signed: SignedBody = parse_body(&body_text)?;
        let wallet = wallet_from_message(&signed.message)?;
        let parsed = verify_and_consume(&state, wallet, &signed, Action::Issue).await?;
        let service_id = required_field(parsed.fields.service_id, "service_id")?;
        let payer = required_field(parsed.fields.payer, "payer")?;
        let pack_id = required_field(parsed.fields.pack_id, "pack_id")?;
        let total_uses = parse_i64(parsed.fields.total_uses, "total_uses")?;
        let validity_seconds = parse_i64(parsed.fields.validity_seconds, "validity_seconds")?;
        let resources_json = required_field(parsed.fields.resources_json, "resources_json")?;
        let resources: Vec<String> = serde_json::from_str(&resources_json)
            .map_err(|e| Error::BadRequest(format!("resources_json: {e}")))?;
        if resources.is_empty() {
            return Err(Error::BadRequest("resources must not be empty".into()));
        }
        let service = load_active_service(&state, &service_id).await?;
        if service.merchant_wallet != wallet {
            return Err(Error::Unauthorized("not service merchant".into()));
        }
        if !resources_subset_of_allowlist(&resources, &service.resources_allowlist) {
            return Err(Error::Forbidden("resources not subset of allowlist".into()));
        }
        if let Some(bundles) = service.pack_bundles.as_ref() {
            let definition = find_pack(Some(bundles), &pack_id)
                .ok_or_else(|| Error::Forbidden("pack_id not present in service catalog".into()))?;
            if definition.get("total_uses").and_then(Value::as_i64) != Some(total_uses) {
                return Err(Error::Forbidden("total_uses does not match catalog".into()));
            }
            if let Some(expected) = definition.get("validity_seconds").and_then(Value::as_i64) {
                if expected != validity_seconds {
                    return Err(Error::Forbidden(
                        "validity_seconds does not match catalog".into(),
                    ));
                }
            }
        }
        let issued = jwt::issue_rs256_token(
            &state.config,
            &service_id,
            &payer,
            &pack_id,
            total_uses,
            validity_seconds,
            resources.clone(),
        )?;
        state
            .require_db()?
            .insert_pack(
                issued.jti,
                &service_id,
                &payer,
                &pack_id,
                total_uses,
                &issued.resources,
                issued.issued_at,
                issued.expires_at,
            )
            .await?;
        Ok(json!({
            "success": true, "token": issued.token, "jti": issued.jti,
            "service_id": service_id, "payer": payer, "pack_id": pack_id,
            "total_uses": total_uses, "remaining_uses": total_uses,
            "resources": resources, "expires_at": issued.expires_at.to_rfc3339()
        }))
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_consume(
    state: Arc<AppState>,
    auth: Option<&str>,
    idempotency_key: Option<&str>,
    body_text: String,
) -> Response<Body> {
    let result = async {
        let key = idempotency_key
            .map(str::trim)
            .filter(|key| (8..=200).contains(&key.len()))
            .ok_or_else(|| Error::BadRequest("Idempotency-Key must be 8-200 characters".into()))?;
        let body: ConsumeBody = parse_body(&body_text)?;
        if body.resource.is_empty() || body.resource.len() > 1000 {
            return Err(Error::BadRequest("invalid resource".into()));
        }
        let token = jwt::decode_bearer_token(auth)?;
        let claims = verify_pack_token(&state, &token).await?;
        let jti = Uuid::parse_str(&claims.jti)
            .map_err(|e| Error::Unauthorized(format!("invalid jti: {e}")))?;
        let pack = state
            .require_db()?
            .get_pack(jti)
            .await?
            .ok_or_else(|| Error::Unauthorized("unknown pack token".into()))?;
        claims_match_pack(&claims, &pack)?;
        if !resource_allowed(&body.resource, &pack.resources) {
            return Err(Error::Forbidden("resource outside pack scope".into()));
        }
        match state
            .require_db()?
            .consume_pack(jti, key, &body.resource)
            .await?
        {
            ConsumeOutcome::Consumed(value) => Ok(json!({
                "success": true, "consumption_id": value.consumption_id,
                "jti": jti, "resource": body.resource,
                "remaining_uses": value.remaining_uses,
                "consumed_at": value.consumed_at.to_rfc3339(), "replayed": value.replayed
            })),
            ConsumeOutcome::NotFound => Err(Error::Unauthorized("unknown pack token".into())),
            ConsumeOutcome::Revoked => Err(Error::Unauthorized("pack revoked".into())),
            ConsumeOutcome::Expired => Err(Error::Unauthorized("pack expired".into())),
            ConsumeOutcome::Exhausted => Err(Error::Exhausted("no uses remaining".into())),
            ConsumeOutcome::IdempotencyConflict => Err(Error::Conflict(
                "Idempotency-Key was already used for a different resource".into(),
            )),
        }
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_revoke(state: Arc<AppState>, body_text: String) -> Response<Body> {
    let result = async {
        let signed: SignedBody = parse_body(&body_text)?;
        let wallet = wallet_from_message(&signed.message)?;
        let parsed = verify_and_consume(&state, wallet, &signed, Action::Revoke).await?;
        let service_id = required_field(parsed.fields.service_id, "service_id")?;
        let jti_text = required_field(parsed.fields.jti, "jti")?;
        let jti = Uuid::parse_str(&jti_text)
            .map_err(|e| Error::BadRequest(format!("invalid jti: {e}")))?;
        if !state
            .require_db()?
            .revoke_pack(jti, &service_id, wallet)
            .await?
        {
            return Err(Error::NotFound("pack not found or already revoked".into()));
        }
        Ok(json!({ "success": true, "jti": jti, "revoked": true }))
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_introspect(state: Arc<AppState>, auth: Option<&str>) -> Response<Body> {
    let result = async {
        let token = jwt::decode_bearer_token(auth)?;
        let claims = verify_pack_token(&state, &token).await?;
        let jti = Uuid::parse_str(&claims.jti)
            .map_err(|e| Error::Unauthorized(format!("invalid jti: {e}")))?;
        let Some(pack) = state.require_db()?.get_pack(jti).await? else {
            return Ok(json!({ "active": false }));
        };
        claims_match_pack(&claims, &pack)?;
        let remaining = pack.total_uses - pack.used_uses;
        let active = pack.revoked_at.is_none() && pack.expires_at > Utc::now() && remaining > 0;
        Ok(json!({
            "active": active, "jti": pack.jti, "service_id": pack.service_id,
            "payer": pack.payer, "pack_id": pack.pack_id,
            "total_uses": pack.total_uses, "used_uses": pack.used_uses,
            "remaining_uses": remaining, "expires_at": pack.expires_at.to_rfc3339(),
            "revoked": pack.revoked_at.is_some()
        }))
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_list_packs(
    state: Arc<AppState>,
    wallet: String,
    body_text: String,
) -> Response<Body> {
    let result = async {
        let body: ListPacksBody = parse_body(&body_text)?;
        verify_and_consume(&state, &wallet, &body.signed, Action::List).await?;
        let before = body.before.as_deref().map(parse_time).transpose()?;
        let (rows, has_more) = state
            .require_db()?
            .list_packs(&wallet, body.service_id.as_deref(), 50, before)
            .await?;
        let next_cursor = has_more
            .then(|| rows.last().map(|row| row.issued_at.to_rfc3339()))
            .flatten();
        let packs: Vec<Value> = rows.iter().map(pack_json).collect();
        Ok(json!({ "packs": packs, "has_more": has_more, "next_cursor": next_cursor }))
    }
    .await;
    into_vercel_response(result)
}

pub async fn handle_revocations(state: Arc<AppState>, query: &str) -> Response<Body> {
    let result = async {
        let map = crate::http_util::parse_query_map(query);
        let service_id = map.get("service_id").ok_or_else(|| Error::BadRequest("service_id required".into()))?;
        let window_start = Utc::now() - chrono::Duration::days(state.config.revocation_window_days);
        let since = map.get("since").map(|value| parse_time(value)).transpose()?.unwrap_or(window_start).max(window_start);
        let (jtis, cursor, complete) = state.require_db()?.list_revocations(service_id, since, 500).await?;
        Ok(json!({ "service_id": service_id, "cursor": cursor.to_rfc3339(), "revoked_jti": jtis, "complete": complete }))
    }.await;
    into_vercel_response(result)
}

pub async fn handle_service_info(state: Arc<AppState>, service_id: String) -> Response<Body> {
    let result = async {
        let row = state.require_db()?.get_service(&service_id).await?.ok_or_else(|| Error::NotFound("service not registered".into()))?;
        Ok(json!({ "service_id": row.service_id, "status": row.status, "service_url": row.service_url, "merchant_wallet": row.merchant_wallet, "resources_allowlist": row.resources_allowlist, "pack_bundles": row.pack_bundles }))
    }.await;
    into_vercel_response(result)
}

pub fn route_options() -> Response<Body> {
    cors_options()
}
pub fn parse_service_wallet(path: &str, suffix: &str) -> Option<String> {
    parse_wallet_path(path, suffix)
}

async fn verify_and_consume(
    state: &AppState,
    wallet: &str,
    signed: &SignedBody,
    expected: Action,
) -> Result<ParsedChallenge, Error> {
    let parsed = challenge_auth::verify_challenge_submission(
        &state.config.hmac_secret,
        wallet,
        &signed.message,
        &signed.signature,
    )
    .map_err(Error::Unauthorized)?;
    if parsed.action != expected {
        return Err(Error::Unauthorized("action mismatch".into()));
    }
    if parsed.wallet != wallet {
        return Err(Error::Unauthorized("wallet mismatch".into()));
    }
    if !state
        .require_db()?
        .consume_nonce(wallet, &parsed.nonce)
        .await?
    {
        return Err(Error::Unauthorized(
            "nonce replay or expired challenge".into(),
        ));
    }
    Ok(parsed)
}

async fn load_active_service(state: &AppState, service_id: &str) -> Result<ServiceRow, Error> {
    let row = state
        .require_db()?
        .get_service(service_id)
        .await?
        .ok_or_else(|| Error::NotFound("service not registered".into()))?;
    if row.status != "active" {
        return Err(Error::Forbidden("service retired".into()));
    }
    Ok(row)
}

async fn verify_pack_token(state: &AppState, token: &str) -> Result<jwt::TokenClaims, Error> {
    let kid = jwt::token_kid(token)?;
    if kid == state.config.key_id {
        return jwt::verify_token(&state.config, token);
    }
    let jwk = state
        .require_db()?
        .get_signing_key(&kid)
        .await?
        .ok_or_else(|| Error::Unauthorized("unknown signing key".into()))?;
    jwt::verify_token_with_jwk(&state.config, token, &jwk)
}

fn parse_body<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, Error> {
    serde_json::from_str(text).map_err(|e| Error::BadRequest(format!("invalid JSON: {e}")))
}
fn wallet_from_message(message: &str) -> Result<&str, Error> {
    message
        .lines()
        .find_map(|line| line.strip_prefix("wallet: "))
        .ok_or_else(|| Error::BadRequest("wallet missing in message".into()))
}
fn required_field(value: Option<String>, name: &str) -> Result<String, Error> {
    value.ok_or_else(|| Error::BadRequest(format!("{name} required in challenge")))
}
fn parse_i64(value: Option<String>, name: &str) -> Result<i64, Error> {
    required_field(value, name)?
        .parse()
        .map_err(|_| Error::BadRequest(format!("invalid {name}")))
}
fn ensure_bound(bound: &Option<String>, actual: &str, name: &str) -> Result<(), Error> {
    if bound.as_deref() == Some(actual) {
        Ok(())
    } else {
        Err(Error::Unauthorized(format!(
            "{name} not bound in challenge"
        )))
    }
}
fn parse_time(value: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|e| Error::BadRequest(format!("invalid timestamp: {e}")))
}

fn claims_match_pack(claims: &jwt::TokenClaims, pack: &PackRow) -> Result<(), Error> {
    if claims.sub != pack.service_id
        || claims.payer != pack.payer
        || claims.pack_id != pack.pack_id
        || claims.total_uses != pack.total_uses
        || serde_json::to_value(&claims.resources).ok().as_ref() != Some(&pack.resources)
    {
        Err(Error::Unauthorized(
            "token claims do not match pack record".into(),
        ))
    } else {
        Ok(())
    }
}

fn pack_json(row: &PackRow) -> Value {
    json!({
        "jti": row.jti, "service_id": row.service_id, "payer": row.payer,
        "pack_id": row.pack_id, "total_uses": row.total_uses, "used_uses": row.used_uses,
        "remaining_uses": row.total_uses-row.used_uses, "resources": row.resources,
        "issued_at": row.issued_at.to_rfc3339(), "expires_at": row.expires_at.to_rfc3339(),
        "revoked_at": row.revoked_at.as_ref().map(DateTime::to_rfc3339)
    })
}
