use crate::error::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub hmac_secret: Vec<u8>,
    pub rsa_private_key_pem: String,
    pub key_id: String,
    pub iss: String,
    pub revocation_window_days: i64,
    pub max_pack_uses: i64,
    pub max_validity_seconds: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        let hmac_secret = required("PACK_AUTH_HMAC_SECRET")?;
        if hmac_secret.len() < 32 {
            return Err(Error::Internal(
                "PACK_AUTH_HMAC_SECRET must be at least 32 bytes".into(),
            ));
        }
        Ok(Self {
            hmac_secret: hmac_secret.into_bytes(),
            rsa_private_key_pem: required("PACK_AUTH_RSA_PRIVATE_KEY_PEM")?,
            key_id: required("PACK_AUTH_KEY_ID")?,
            iss: required("PACK_AUTH_ISS")?,
            revocation_window_days: env_i64("PACK_AUTH_REVOCATION_WINDOW_DAYS", 7),
            max_pack_uses: env_i64("PACK_AUTH_MAX_USES", 1_000_000).max(1),
            max_validity_seconds: env_i64(
                "PACK_AUTH_MAX_VALIDITY_SECONDS",
                10 * 365 * 24 * 60 * 60,
            )
            .max(3600),
        })
    }
}

fn required(name: &str) -> Result<String, Error> {
    std::env::var(name).map_err(|_| Error::Internal(format!("{name} not set")))
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
