//! Wallet-signed merchant writes: HMAC-bound challenge + Ed25519 signature.

use {
    hmac::{Hmac, Mac},
    sha2::Sha256,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    std::{
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    },
    subtle::ConstantTimeEq,
};

type HmacSha256 = Hmac<Sha256>;
pub const DOMAIN: &str = "x402 pack auth v1";
const HMAC_PREFIX: &str = "hmac_sha256_hex: ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Register,
    Update,
    Retire,
    Issue,
    Revoke,
    List,
    Session,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Update => "update",
            Self::Retire => "retire",
            Self::Issue => "issue",
            Self::Revoke => "revoke",
            Self::List => "list",
            Self::Session => "session",
        }
    }
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "register" => Ok(Self::Register),
            "update" => Ok(Self::Update),
            "retire" => Ok(Self::Retire),
            "issue" => Ok(Self::Issue),
            "revoke" => Ok(Self::Revoke),
            "list" => Ok(Self::List),
            "session" => Ok(Self::Session),
            _ => Err(format!("unknown action: {value}")),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BoundFields {
    pub service_id: Option<String>,
    pub service_url: Option<String>,
    pub resources_allowlist_json: Option<String>,
    pub pack_bundles_json: Option<String>,
    pub payer: Option<String>,
    pub pack_id: Option<String>,
    pub total_uses: Option<String>,
    pub validity_seconds: Option<String>,
    pub resources_json: Option<String>,
    pub jti: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChallengeBuildParams {
    pub action: Action,
    pub fields: BoundFields,
}

#[derive(Debug, Clone)]
pub struct ParsedChallenge {
    pub action: Action,
    pub wallet: String,
    pub nonce: String,
    pub fields: BoundFields,
}

pub fn build_challenge_message(
    secret: &[u8],
    wallet: &str,
    ttl: u64,
    params: ChallengeBuildParams,
) -> Result<(String, u64), String> {
    if ttl == 0 || ttl > 3600 {
        return Err("ttl must be 1..=3600".into());
    }
    Pubkey::from_str(wallet).map_err(|_| "invalid wallet pubkey")?;
    let issued = now();
    let expires = issued.saturating_add(ttl);
    let nonce = random_nonce()?;
    let mut lines = vec![
        DOMAIN.into(),
        format!("wallet: {wallet}"),
        format!("issued_unix: {issued}"),
        format!("expires_unix: {expires}"),
        format!("nonce: {nonce}"),
        format!("action: {}", params.action.as_str()),
    ];
    push_fields(&mut lines, &params.action, &params.fields);
    lines.push(String::new());
    let preimage = lines.join("\n");
    let mac = hmac_hex(secret, &preimage)?;
    Ok((format!("{preimage}{HMAC_PREFIX}{mac}"), expires))
}

pub fn verify_challenge_submission(
    secret: &[u8],
    wallet: &str,
    message: &str,
    signature: &str,
) -> Result<ParsedChallenge, String> {
    let public_key = Pubkey::from_str(wallet).map_err(|_| "invalid wallet pubkey")?;
    let signature = decode_signature(signature)?;
    let index = message.rfind(HMAC_PREFIX).ok_or("missing HMAC line")?;
    let preimage = &message[..index];
    let supplied = &message[index + HMAC_PREFIX.len()..];
    let expected = hmac_hex(secret, preimage)?;
    if supplied.len() != 64 || !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes())) {
        return Err("HMAC mismatch".into());
    }
    if !signature.verify(public_key.as_ref(), message.as_bytes()) {
        return Err("invalid signature".into());
    }
    let lines: Vec<&str> = preimage.lines().collect();
    if lines.len() < 6 || lines[0] != DOMAIN {
        return Err("invalid challenge format".into());
    }
    let parsed_wallet = value(lines[1], "wallet: ")?;
    if parsed_wallet != wallet {
        return Err("wallet mismatch".into());
    }
    let issued = value(lines[2], "issued_unix: ")?
        .parse::<u64>()
        .map_err(|_| "invalid issued_unix")?;
    let expires = value(lines[3], "expires_unix: ")?
        .parse::<u64>()
        .map_err(|_| "invalid expires_unix")?;
    if now() < issued || now() > expires {
        return Err("challenge expired or issued in future".into());
    }
    let nonce = value(lines[4], "nonce: ")?;
    if nonce.len() != 32 || !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid nonce".into());
    }
    let action = Action::parse(value(lines[5], "action: ")?)?;
    let mut fields = BoundFields::default();
    for line in &lines[6..] {
        macro_rules! take {
            ($prefix:literal, $field:ident) => {
                if let Some(v) = line.strip_prefix($prefix) {
                    fields.$field = Some(v.into());
                    continue;
                }
            };
        }
        take!("service_id: ", service_id);
        take!("service_url: ", service_url);
        take!("resources_allowlist_json: ", resources_allowlist_json);
        take!("pack_bundles_json: ", pack_bundles_json);
        take!("payer: ", payer);
        take!("pack_id: ", pack_id);
        take!("total_uses: ", total_uses);
        take!("validity_seconds: ", validity_seconds);
        take!("resources_json: ", resources_json);
        take!("jti: ", jti);
        if !line.is_empty() {
            return Err(format!("unknown challenge field: {line}"));
        }
    }
    Ok(ParsedChallenge {
        action,
        wallet: wallet.into(),
        nonce: nonce.into(),
        fields,
    })
}

pub fn minify_json_array(values: &[String]) -> Result<String, String> {
    serde_json::to_string(values).map_err(|e| e.to_string())
}

fn push_fields(lines: &mut Vec<String>, action: &Action, fields: &BoundFields) {
    let mut push = |name: &str, value: &Option<String>| {
        if let Some(value) = value {
            lines.push(format!("{name}: {value}"));
        }
    };
    push("service_id", &fields.service_id);
    match action {
        Action::Register => {
            push("service_url", &fields.service_url);
            push("resources_allowlist_json", &fields.resources_allowlist_json);
            push("pack_bundles_json", &fields.pack_bundles_json);
        }
        Action::Update => {
            push("resources_allowlist_json", &fields.resources_allowlist_json);
            push("pack_bundles_json", &fields.pack_bundles_json);
        }
        Action::Retire => {}
        Action::Issue => {
            push("payer", &fields.payer);
            push("pack_id", &fields.pack_id);
            push("total_uses", &fields.total_uses);
            push("validity_seconds", &fields.validity_seconds);
            push("resources_json", &fields.resources_json);
        }
        Action::Revoke | Action::Session => push("jti", &fields.jti),
        Action::List => {}
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn value<'a>(line: &'a str, prefix: &str) -> Result<&'a str, String> {
    line.strip_prefix(prefix)
        .ok_or_else(|| format!("expected {prefix}"))
}
fn random_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "RNG failure")?;
    Ok(hex(&bytes))
}
fn hmac_hex(secret: &[u8], data: &str) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| "invalid HMAC key")?;
    mac.update(data.as_bytes());
    Ok(hex(&mac.finalize().into_bytes()))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_signature(value: &str) -> Result<Signature, String> {
    if let Ok(signature) = Signature::from_str(value.trim()) {
        return Ok(signature);
    }
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD
        .decode(value.trim())
        .map_err(|_| "invalid signature encoding")?;
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| "invalid signature length")?;
    Ok(Signature::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_signer::Signer;
    #[test]
    fn issue_round_trip() {
        let keypair = solana_keypair::Keypair::new();
        let wallet = keypair.pubkey().to_string();
        let params = ChallengeBuildParams {
            action: Action::Issue,
            fields: BoundFields {
                service_id: Some("api.example.com".into()),
                payer: Some("buyer".into()),
                pack_id: Some("ten".into()),
                total_uses: Some("10".into()),
                validity_seconds: Some("86400".into()),
                resources_json: Some("[\"/data\"]".into()),
                ..Default::default()
            },
        };
        let (message, _) = build_challenge_message(
            b"a-secret-that-is-longer-than-32-bytes",
            &wallet,
            600,
            params,
        )
        .unwrap();
        let signature = keypair.sign_message(message.as_bytes()).to_string();
        let parsed = verify_challenge_submission(
            b"a-secret-that-is-longer-than-32-bytes",
            &wallet,
            &message,
            &signature,
        )
        .unwrap();
        assert_eq!(parsed.fields.total_uses.as_deref(), Some("10"));
    }

    #[test]
    fn session_challenge_binds_pack_to_wallet() {
        let keypair = solana_keypair::Keypair::new();
        let wallet = keypair.pubkey().to_string();
        let params = ChallengeBuildParams {
            action: Action::Session,
            fields: BoundFields {
                service_id: Some("api.example.com".into()),
                jti: Some("55a44da0-34ee-45a9-9c77-2f6bf7b4eb44".into()),
                ..Default::default()
            },
        };
        let (message, _) = build_challenge_message(
            b"a-secret-that-is-longer-than-32-bytes",
            &wallet,
            600,
            params,
        )
        .unwrap();
        let signature = keypair.sign_message(message.as_bytes()).to_string();
        let parsed = verify_challenge_submission(
            b"a-secret-that-is-longer-than-32-bytes",
            &wallet,
            &message,
            &signature,
        )
        .unwrap();
        assert_eq!(parsed.action, Action::Session);
        assert_eq!(parsed.wallet, wallet);
        assert_eq!(
            parsed.fields.jti.as_deref(),
            Some("55a44da0-34ee-45a9-9c77-2f6bf7b4eb44")
        );
    }
}
