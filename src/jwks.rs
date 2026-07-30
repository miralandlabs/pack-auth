use {
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine},
    rsa::{
        pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts, RsaPrivateKey,
    },
    serde_json::{json, Value},
};

use crate::{config::Config, error::Error};

pub fn public_jwk_from_private_pem(pem: &str, kid: &str) -> Result<Value, Error> {
    let private = RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|error| Error::Internal(format!("invalid RSA private key: {error}")))?;
    let public = private.to_public_key();
    Ok(json!({
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
    }))
}

pub fn build_jwks(current: &Config, db_keys: Vec<(String, Value)>) -> Value {
    let mut keys = Vec::new();
    match public_jwk_from_private_pem(&current.rsa_private_key_pem, &current.key_id) {
        Ok(key) => keys.push(key),
        Err(error) => tracing::error!(%error, "failed to build current JWK"),
    }
    for (kid, key) in db_keys {
        if !keys
            .iter()
            .any(|item| item.get("kid").and_then(Value::as_str) == Some(kid.as_str()))
        {
            keys.push(key);
        }
    }
    json!({ "keys": keys })
}
