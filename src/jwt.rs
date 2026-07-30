use {
    chrono::{DateTime, Utc},
    jsonwebtoken::{
        decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
    },
    rsa::{
        pkcs1::DecodeRsaPrivateKey,
        pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding},
        RsaPrivateKey,
    },
    serde::{Deserialize, Serialize},
    serde_json::Value,
    uuid::Uuid,
};

use crate::{config::Config, error::Error};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub sub: String,
    pub payer: String,
    pub pack_id: String,
    pub total_uses: i64,
    pub resources: Vec<String>,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

pub struct IssuedToken {
    pub token: String,
    pub jti: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resources: Value,
}

pub fn issue_rs256_token(
    config: &Config,
    service_id: &str,
    payer: &str,
    pack_id: &str,
    total_uses: i64,
    validity_seconds: i64,
    resources: Vec<String>,
) -> Result<IssuedToken, Error> {
    if !(1..=config.max_pack_uses).contains(&total_uses) {
        return Err(Error::BadRequest(
            "total_uses is outside the configured range".into(),
        ));
    }
    if !(3600..=config.max_validity_seconds).contains(&validity_seconds) {
        return Err(Error::BadRequest(
            "validity_seconds is outside the configured range".into(),
        ));
    }
    let issued_at = Utc::now();
    let expires_at = issued_at + chrono::Duration::seconds(validity_seconds);
    let jti = Uuid::new_v4();
    let claims = TokenClaims {
        iss: config.iss.clone(),
        sub: service_id.into(),
        payer: payer.into(),
        pack_id: pack_id.into(),
        total_uses,
        resources: resources.clone(),
        jti: jti.to_string(),
        iat: issued_at.timestamp(),
        exp: expires_at.timestamp(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(config.key_id.clone());
    let key = EncodingKey::from_rsa_pem(config.rsa_private_key_pem.as_bytes())
        .map_err(|error| Error::Internal(format!("RSA encoding key: {error}")))?;
    let token = encode(&header, &claims, &key)
        .map_err(|error| Error::Internal(format!("JWT sign: {error}")))?;
    Ok(IssuedToken {
        token,
        jti,
        issued_at,
        expires_at,
        resources: serde_json::to_value(resources)
            .map_err(|error| Error::Internal(format!("resources JSON: {error}")))?,
    })
}

pub fn decode_bearer_token(auth_header: Option<&str>) -> Result<String, Error> {
    auth_header
        .and_then(|header| header.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(String::from)
        .ok_or_else(|| Error::Unauthorized("expected a non-empty Bearer token".into()))
}

pub fn verify_token(config: &Config, token: &str) -> Result<TokenClaims, Error> {
    let private = RsaPrivateKey::from_pkcs8_pem(&config.rsa_private_key_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&config.rsa_private_key_pem))
        .map_err(|error| Error::Internal(format!("invalid RSA private key: {error}")))?;
    let public_pem = private
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| Error::Internal(format!("RSA public key: {error}")))?;
    let key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
        .map_err(|error| Error::Internal(format!("RSA decoding key: {error}")))?;
    decode_claims(config, token, &key)
}

pub fn token_kid(token: &str) -> Result<String, Error> {
    decode_header(token)
        .map_err(|error| Error::Unauthorized(format!("invalid token header: {error}")))?
        .kid
        .ok_or_else(|| Error::Unauthorized("token has no kid".into()))
}

pub fn verify_token_with_jwk(
    config: &Config,
    token: &str,
    jwk: &Value,
) -> Result<TokenClaims, Error> {
    let n = jwk
        .get("n")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Internal("stored RSA JWK has no n".into()))?;
    let e = jwk
        .get("e")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Internal("stored RSA JWK has no e".into()))?;
    let key = DecodingKey::from_rsa_components(n, e)
        .map_err(|error| Error::Internal(format!("stored RSA JWK: {error}")))?;
    decode_claims(config, token, &key)
}

fn decode_claims(config: &Config, token: &str, key: &DecodingKey) -> Result<TokenClaims, Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[config.iss.as_str()]);
    decode::<TokenClaims>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|error| Error::Unauthorized(format!("invalid token: {error}")))
}
