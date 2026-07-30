use serde_json::Value;

pub fn resources_subset_of_allowlist(resources: &[String], allowlist: &Value) -> bool {
    let allow: Vec<&str> = allowlist
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    allow.contains(&"*")
        || resources
            .iter()
            .all(|resource| resource != "*" && allow.contains(&resource.as_str()))
}

pub fn resource_allowed(resource: &str, resources: &Value) -> bool {
    resources
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|allowed| allowed == "*" || allowed == resource)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checks_resource_scope() {
        assert!(resources_subset_of_allowlist(
            &["/a".into()],
            &json!(["/a", "/b"])
        ));
        assert!(!resources_subset_of_allowlist(
            &["/c".into()],
            &json!(["/a"])
        ));
        assert!(resource_allowed("/anything", &json!(["*"])));
    }
}
