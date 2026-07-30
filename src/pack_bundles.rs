//! Validation and catalog projection for usage-pack metadata.

use {
    crate::error::Error,
    serde_json::{json, Value},
    std::collections::HashSet,
};

const MAX_TAGS: usize = 10;
const CATEGORIES: &[&str] = &[
    "social-media",
    "blockchain",
    "ai-ml",
    "finance",
    "developer-tools",
    "content",
    "communication",
    "other",
];

pub fn validate_pack_bundles(value: Option<&Value>, max_uses: i64) -> Result<(), Error> {
    let Some(value) = value else { return Ok(()) };
    let root = value
        .as_object()
        .ok_or_else(|| Error::BadRequest("pack_bundles must be an object".into()))?;
    validate_display(root.get("display"))?;
    let packs = root
        .get("packs")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| Error::BadRequest("pack_bundles.packs must be non-empty".into()))?;
    let mut ids = HashSet::new();
    for (index, pack) in packs.iter().enumerate() {
        let object = pack.as_object().ok_or_else(|| {
            Error::BadRequest(format!("pack_bundles.packs[{index}] must be an object"))
        })?;
        let id = required_string(object, "id", index)?;
        let name = required_string(object, "name", index)?;
        if id.len() > 64
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err(Error::BadRequest(format!(
                "pack_bundles.packs[{index}].id is invalid"
            )));
        }
        if !ids.insert(id) {
            return Err(Error::BadRequest("pack ids must be unique".into()));
        }
        reject_html(name, "pack name")?;
        let total_uses = object
            .get("total_uses")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                Error::BadRequest(format!(
                    "pack_bundles.packs[{index}].total_uses must be an integer"
                ))
            })?;
        if !(1..=max_uses).contains(&total_uses) {
            return Err(Error::BadRequest(format!(
                "pack_bundles.packs[{index}].total_uses must be 1..={max_uses}"
            )));
        }
        if let Some(price) = object.get("price_usdc").and_then(Value::as_f64) {
            if !price.is_finite() || price < 0.0 {
                return Err(Error::BadRequest("price_usdc must be non-negative".into()));
            }
        }
        if let Some(seconds) = object.get("validity_seconds").and_then(Value::as_i64) {
            if seconds < 3600 {
                return Err(Error::BadRequest(
                    "validity_seconds must be at least 3600".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn find_pack<'a>(value: Option<&'a Value>, pack_id: &str) -> Option<&'a Value> {
    value?
        .get("packs")?
        .as_array()?
        .iter()
        .find(|pack| pack.get("id").and_then(Value::as_str) == Some(pack_id))
}

pub fn extract_catalog_index(value: Option<&Value>) -> (Option<String>, Value) {
    let display = value.and_then(|v| v.get("display"));
    let category = display
        .and_then(|d| d.get("category"))
        .and_then(Value::as_str)
        .map(String::from);
    let mut tags: Vec<String> = display
        .and_then(|d| d.get("tags"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_lowercase)
        .take(MAX_TAGS)
        .collect();
    tags.sort();
    tags.dedup();
    (category, json!(tags))
}

pub fn display_block(value: Option<&Value>) -> Option<Value> {
    value.and_then(|v| v.get("display")).cloned()
}

pub fn pricing_summary(value: Option<&Value>) -> Value {
    let packs = value.and_then(|v| v.get("packs")).and_then(Value::as_array);
    let Some(packs) = packs else {
        return json!({ "configured": false, "starting_at_usdc": null, "pack_count": 0 });
    };
    let starting = packs
        .iter()
        .filter_map(|pack| pack.get("price_usdc").and_then(Value::as_f64))
        .reduce(f64::min);
    json!({
        "configured": true,
        "starting_at_usdc": starting,
        "pack_count": packs.len(),
    })
}

fn validate_display(value: Option<&Value>) -> Result<(), Error> {
    let display = value
        .and_then(Value::as_object)
        .ok_or_else(|| Error::BadRequest("pack_bundles.display is required".into()))?;
    let name = display
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && name.len() <= 200)
        .ok_or_else(|| Error::BadRequest("display.name must be 1-200 chars".into()))?;
    reject_html(name, "display.name")?;
    let category = display
        .get("category")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::BadRequest("display.category is required".into()))?;
    if !CATEGORIES.contains(&category) {
        return Err(Error::BadRequest(format!(
            "display.category must be one of: {}",
            CATEGORIES.join(", ")
        )));
    }
    if let Some(tags) = display.get("tags") {
        let tags = tags
            .as_array()
            .filter(|tags| tags.len() <= MAX_TAGS)
            .ok_or_else(|| {
                Error::BadRequest("display.tags must contain at most 10 items".into())
            })?;
        for tag in tags {
            let tag = tag
                .as_str()
                .filter(|tag| !tag.is_empty() && tag.len() <= 64)
                .ok_or_else(|| Error::BadRequest("invalid display tag".into()))?;
            reject_html(tag, "display tag")?;
        }
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<&'a str, Error> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::BadRequest(format!("packs[{index}].{field} is required")))
}

fn reject_html(value: &str, field: &str) -> Result<(), Error> {
    let lower = value.to_lowercase();
    if lower.contains("<script") || lower.contains("javascript:") {
        Err(Error::BadRequest(format!(
            "{field} contains disallowed content"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_pack_catalog() {
        let value = json!({
            "display": { "name": "Demo", "category": "developer-tools" },
            "packs": [{ "id": "starter-10", "name": "10 calls", "total_uses": 10, "price_usdc": 1.5 }]
        });
        assert!(validate_pack_bundles(Some(&value), 1000).is_ok());
        assert_eq!(
            find_pack(Some(&value), "starter-10").unwrap()["total_uses"],
            10
        );
    }
}
