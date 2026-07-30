use vercel_runtime::{Body, Response, StatusCode};

pub fn add_cors_headers(builder: http::response::Builder) -> http::response::Builder {
    let origin = std::env::var("PACK_AUTH_ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3001".into());
    builder
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .header("Vary", "Origin")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, Idempotency-Key",
        )
}

pub fn json_response_with_cookie<T: serde::Serialize>(
    status: u16,
    value: &T,
    cookie: &str,
) -> Response<Body> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    add_cors_headers(
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-store")
            .header("Set-Cookie", cookie),
    )
    .body(Body::Text(
        serde_json::to_string(value).unwrap_or_else(|_| "{}".into()),
    ))
    .expect("valid json response")
}

pub fn parse_cookie<'a>(cookie_header: Option<&'a str>, name: &str) -> Option<&'a str> {
    cookie_header?.split(';').find_map(|item| {
        let (key, value) = item.trim().split_once('=')?;
        (key == name && !value.is_empty()).then_some(value)
    })
}

pub fn json_response<T: serde::Serialize>(status: u16, value: &T) -> Response<Body> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    add_cors_headers(
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-store"),
    )
    .body(Body::Text(
        serde_json::to_string(value).unwrap_or_else(|_| "{}".into()),
    ))
    .expect("valid json response")
}

pub fn cors_options() -> Response<Body> {
    add_cors_headers(
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Access-Control-Max-Age", "86400"),
    )
    .body(Body::Empty)
    .expect("valid CORS response")
}

pub fn parse_wallet_path(path: &str, suffix: &str) -> Option<String> {
    let rest = path.strip_prefix("/v1/services/")?;
    let wallet = rest.strip_suffix(suffix)?.trim_end_matches('/');
    (!wallet.is_empty()).then(|| wallet.to_string())
}

pub fn parse_query_map(query: &str) -> std::collections::HashMap<String, String> {
    if query.trim().is_empty() {
        return std::collections::HashMap::new();
    }
    serde_qs::from_str(query).unwrap_or_default()
}
