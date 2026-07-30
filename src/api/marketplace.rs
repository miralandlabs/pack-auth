use {
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine},
    chrono::{DateTime, Utc},
    serde_json::{json, Value},
    std::sync::Arc,
    vercel_runtime::{Body, Response},
};

use crate::{
    db::MarketplaceRow,
    error::{into_vercel_response, Error},
    pack_bundles::{display_block, pricing_summary},
    state::AppState,
};

pub async fn handle_marketplace_list(state: Arc<AppState>, query: &str) -> Response<Body> {
    let result = async {
        let map = crate::http_util::parse_query_map(query);
        let limit = map.get("limit").and_then(|v| v.parse().ok()).unwrap_or(20_i64).clamp(1, 100);
        let tags: Vec<String> = map.get("tags").map(|v| v.split(',').map(str::trim).filter(|v| !v.is_empty()).map(str::to_lowercase).collect()).unwrap_or_default();
        let cursor = map.get("cursor").map(|value| decode_cursor(value)).transpose()?;
        let (rows, has_more) = state.require_db()?.list_marketplace(
            map.get("category").map(String::as_str), &tags, map.get("q").map(String::as_str), limit, cursor
        ).await?;
        let next_cursor = has_more.then(|| rows.last().map(|row| encode_cursor(row.updated_at, &row.service_id))).flatten();
        let packs: Vec<Value> = rows.iter().map(list_item).collect();
        Ok(json!({
            "packs": packs,
            "pagination": { "next_cursor": next_cursor, "has_more": has_more },
            "notice": "Catalog metadata is advisory; authoritative purchase pricing comes from the seller's live 402 response."
        }))
    }.await;
    into_vercel_response(result)
}

pub async fn handle_marketplace_detail(state: Arc<AppState>, service_id: String) -> Response<Body> {
    let result = async {
        crate::service_id::validate_service_id(&service_id)?;
        let row = state
            .require_db()?
            .get_marketplace(&service_id)
            .await?
            .ok_or_else(|| Error::NotFound("pack product not found".into()))?;
        let bundles = row.pack_bundles.as_ref();
        Ok(json!({
            "service_id": row.service_id,
            "merchant_wallet": row.merchant_wallet,
            "service_url": row.service_url,
            "display": display_block(bundles),
            "packs": bundles.and_then(|v| v.get("packs")),
            "pricing_summary": pricing_summary(bundles),
            "resources_allowlist": row.resources_allowlist,
            "created_at": row.created_at.to_rfc3339(),
            "updated_at": row.updated_at.to_rfc3339()
        }))
    }
    .await;
    into_vercel_response(result)
}

fn encode_cursor(time: DateTime<Utc>, service_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{}|{service_id}", time.to_rfc3339()))
}

fn decode_cursor(cursor: &str) -> Result<(DateTime<Utc>, String), Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| Error::BadRequest("invalid cursor".into()))?;
    let value = String::from_utf8(bytes).map_err(|_| Error::BadRequest("invalid cursor".into()))?;
    let (time, service_id) = value
        .split_once('|')
        .ok_or_else(|| Error::BadRequest("invalid cursor".into()))?;
    let time = DateTime::parse_from_rfc3339(time)
        .map_err(|_| Error::BadRequest("invalid cursor timestamp".into()))?
        .with_timezone(&Utc);
    Ok((time, service_id.into()))
}

fn list_item(row: &MarketplaceRow) -> Value {
    json!({
        "service_id": row.service_id,
        "display": display_block(row.pack_bundles.as_ref()),
        "pricing_summary": pricing_summary(row.pack_bundles.as_ref())
    })
}
