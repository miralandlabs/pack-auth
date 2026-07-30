use crate::error::Error;

pub fn validate_service_id(service_id: &str) -> Result<(), Error> {
    let id = service_id.trim();
    if id.is_empty() || id.len() > 253 || id.contains(' ') || id.contains('/') {
        return Err(Error::BadRequest("invalid service_id".into()));
    }
    let dns_style = id.contains('.') && id.split('.').all(|part| !part.is_empty());
    let wallet_style = id
        .split_once(':')
        .is_some_and(|(prefix, slug)| !prefix.is_empty() && slug.len() >= 2);
    if dns_style || wallet_style {
        Ok(())
    } else {
        Err(Error::BadRequest(
            "service_id must be DNS-style or wallet-qualified".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_namespaced_ids() {
        assert!(validate_service_id("api.example.com").is_ok());
        assert!(validate_service_id("wallet:demo").is_ok());
        assert!(validate_service_id("demo").is_err());
    }
}
