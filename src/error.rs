use {
    chrono::Utc,
    serde::Serialize,
    serde_json::json,
    vercel_runtime::{Body, Response, StatusCode},
};

#[derive(Debug)]
pub enum Error {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    Exhausted(String),
    ServiceUnavailable(String),
    Internal(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (label, message) = match self {
            Self::BadRequest(m) => ("Bad Request", m),
            Self::Unauthorized(m) => ("Unauthorized", m),
            Self::Forbidden(m) => ("Forbidden", m),
            Self::NotFound(m) => ("Not Found", m),
            Self::Conflict(m) => ("Conflict", m),
            Self::Exhausted(m) => ("Pack Exhausted", m),
            Self::ServiceUnavailable(m) => ("Service Unavailable", m),
            Self::Internal(m) => ("Internal Error", m),
        };
        write!(f, "{label}: {message}")
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn to_vercel_response(&self) -> Response<Body> {
        let (status, code, message) = match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", m),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", m),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, "FORBIDDEN", m),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, "NOT_FOUND", m),
            Self::Conflict(m) => (StatusCode::CONFLICT, "CONFLICT", m),
            Self::Exhausted(m) => (StatusCode::PAYMENT_REQUIRED, "PACK_EXHAUSTED", m),
            Self::ServiceUnavailable(m) => {
                (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", m)
            }
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", m),
        };
        let builder = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .header(
                "X-Date",
                Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            );
        crate::http_util::add_cors_headers(builder)
            .body(Body::Text(
                json!({ "error": code, "message": message }).to_string(),
            ))
            .expect("valid error response")
    }
}

pub fn into_vercel_response<T: Serialize>(result: Result<T, Error>) -> Response<Body> {
    match result {
        Ok(value) => crate::http_util::json_response(200, &value),
        Err(error) => error.to_vercel_response(),
    }
}
