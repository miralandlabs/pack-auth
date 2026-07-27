use {
    pack_auth::{api, http_util, state::AppState},
    std::sync::Arc,
    tracing_subscriber::{fmt, EnvFilter},
    vercel_runtime::{run, Body, Request, Response, StatusCode},
};

const MAX_BODY_SIZE: usize = 1_048_576;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("pack_auth=info,server_log=info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .try_init();
    let state = Arc::new(AppState::new()?);

    run(move |request: Request| {
        let state = Arc::clone(&state);
        async move { Ok(route(state, request).await) }
    })
    .await
}

async fn route(state: Arc<AppState>, request: Request) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or_default().to_string();
    let authorization = header(&request, "authorization");
    let idempotency_key = header(&request, "idempotency-key");
    let body = match body_to_string(request.into_body()) {
        Ok(body) => body,
        Err(message) => {
            return http_util::json_response(
                400,
                &serde_json::json!({ "error": "BAD_REQUEST", "message": message }),
            )
        }
    };

    if method == http::Method::OPTIONS {
        return api::route_options();
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/health") => api::handle_health(state).await,
        ("GET", "/.well-known/jwks.json") => api::handle_jwks(state).await,
        ("GET", "/openapi.json") => {
            let document: serde_json::Value =
                serde_json::from_str(include_str!("../../public/openapi.json"))
                    .expect("valid embedded OpenAPI");
            http_util::json_response(200, &document)
        }
        ("GET", path) if path.starts_with("/v1/services/") && path.ends_with("/challenge") => {
            wallet_route(state, path, "/challenge", |state, wallet| {
                api::handle_challenge(state, wallet, &query)
            })
            .await
        }
        ("POST", path) if path.starts_with("/v1/services/") && path.ends_with("/register") => {
            wallet_route(state, path, "/register", |state, wallet| {
                api::handle_register(state, wallet, body)
            })
            .await
        }
        ("POST", path) if path.starts_with("/v1/services/") && path.ends_with("/update") => {
            wallet_route(state, path, "/update", |state, wallet| {
                api::handle_update(state, wallet, body)
            })
            .await
        }
        ("POST", path) if path.starts_with("/v1/services/") && path.ends_with("/retire") => {
            wallet_route(state, path, "/retire", |state, wallet| {
                api::handle_retire(state, wallet, body)
            })
            .await
        }
        ("POST", path) if path.starts_with("/v1/services/") && path.ends_with("/packs") => {
            wallet_route(state, path, "/packs", |state, wallet| {
                api::handle_list_packs(state, wallet, body)
            })
            .await
        }
        ("POST", "/v1/packs/issue") => api::handle_issue(state, body).await,
        ("POST", "/v1/packs/consume") => {
            api::handle_consume(
                state,
                authorization.as_deref(),
                idempotency_key.as_deref(),
                body,
            )
            .await
        }
        ("POST", "/v1/packs/revoke") => api::handle_revoke(state, body).await,
        ("POST", "/v1/packs/introspect") => {
            api::handle_introspect(state, authorization.as_deref()).await
        }
        ("GET", "/v1/revocations") => api::handle_revocations(state, &query).await,
        ("GET", "/v1/marketplace/packs") => api::handle_marketplace_list(state, &query).await,
        ("GET", path) if path.starts_with("/v1/marketplace/packs/") => {
            let service_id = path
                .trim_start_matches("/v1/marketplace/packs/")
                .to_string();
            if service_id.is_empty() {
                not_found()
            } else {
                api::handle_marketplace_detail(state, service_id).await
            }
        }
        ("GET", path) if path.starts_with("/v1/info/") => {
            let service_id = path.trim_start_matches("/v1/info/").to_string();
            if service_id.is_empty() {
                not_found()
            } else {
                api::handle_service_info(state, service_id).await
            }
        }
        _ => not_found(),
    }
}

async fn wallet_route<F, Fut>(
    state: Arc<AppState>,
    path: &str,
    suffix: &str,
    handler: F,
) -> Response<Body>
where
    F: FnOnce(Arc<AppState>, String) -> Fut,
    Fut: std::future::Future<Output = Response<Body>>,
{
    match api::parse_service_wallet(path, suffix) {
        Some(wallet) => handler(state, wallet).await,
        None => not_found(),
    }
}

fn header(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(String::from)
}

fn body_to_string(body: Body) -> Result<String, String> {
    let length = match &body {
        Body::Text(value) => value.len(),
        Body::Binary(value) => value.len(),
        Body::Empty => 0,
    };
    if length > MAX_BODY_SIZE {
        return Err(format!(
            "request body too large (max {MAX_BODY_SIZE} bytes)"
        ));
    }
    match body {
        Body::Text(value) => Ok(value),
        Body::Binary(value) => String::from_utf8(value).map_err(|_| "body is not UTF-8".into()),
        Body::Empty => Ok(String::new()),
    }
}

fn not_found() -> Response<Body> {
    http_util::add_cors_headers(
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain"),
    )
    .body(Body::Text("Not found".into()))
    .expect("valid response")
}
