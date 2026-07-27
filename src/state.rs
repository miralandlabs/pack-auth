use {
    crate::{config::Config, db::AuthDb, error::Error, jwks},
    std::sync::Arc,
};

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Option<Arc<AuthDb>>,
}

impl AppState {
    pub fn new() -> Result<Self, Error> {
        let config = Arc::new(Config::from_env()?);
        let db = AuthDb::from_env_var("DATABASE_URL")
            .transpose()
            .map_err(|error| {
                tracing::warn!(%error, "DATABASE_URL set but connection failed");
                error
            })?
            .map(Arc::new);
        Ok(Self { config, db })
    }

    pub fn require_db(&self) -> Result<Arc<AuthDb>, Error> {
        self.db
            .clone()
            .ok_or_else(|| Error::ServiceUnavailable("DATABASE_URL not configured".into()))
    }

    pub async fn jwks_document(&self) -> serde_json::Value {
        let db_keys = match &self.db {
            Some(db) => db.list_signing_keys().await.unwrap_or_default(),
            None => Vec::new(),
        };
        jwks::build_jwks(&self.config, db_keys)
    }
}
