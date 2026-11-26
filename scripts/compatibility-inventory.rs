//! 复用现有 syn 参考生成器检查公开类型及真实适配器路由，新增边界必须显式归类。
use super::{ast, routes};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

fn inventory(root: &std::path::Path) -> Value {
    let sources = ast::Sources::load(root);
    let schemas: Vec<Value> = memoswish_protocol::all_schemas()
        .into_iter()
        .map(|(_, schema)| serde_json::to_value(schema).unwrap())
        .collect();
    let mut named = BTreeSet::new();
    for schema in &schemas {
        named.insert(schema["title"].as_str().unwrap().to_owned());
        if let Some(defs) = schema["$defs"].as_object() {
            named.extend(defs.keys().cloned());
        }
    }
    let mut types = BTreeMap::new();
    let mut adapters = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for source in &sources.files {
        if source.path.starts_with("server/crates/memoswish-protocol/src/") {
            for item in &source.syntax.items {
                let name = match item {
                    syn::Item::Struct(item) if matches!(item.vis, syn::Visibility::Public(_)) => &item.ident,
                    syn::Item::Enum(item) if matches!(item.vis, syn::Visibility::Public(_)) => &item.ident,
                    _ => continue,
                }
                .to_string();
                assert!(named.contains(&name), "unregistered public protocol DTO: {name}");
                assert!(types.insert(name, source.path.clone()).is_none(), "duplicate public DTO");
            }
        }
        if source.path.starts_with("server/crates/memoswishd/src/") {
            let mut routes = routes::Inventory::new(&source.path);
            routes.visit_file(&source.syntax);
            for route in routes.routes {
                if (route.path.starts_with("/v1/") || route.path.starts_with("/assets/")) && route.methods != "HEAD" {
                    paths.insert((route.source, route.methods, route.path, route.handler));
                }
            }
        }
        if [
            "memoswish-content/src/service.rs",
            "memoswish-content/src/apkg/mod.rs",
            "memoswish-auth/src/quota.rs",
            "memoswishd/src/api.rs",
            "memoswishd/src/oidc.rs",
            "memoswishd/src/sessions.rs",
            "memoswishd/src/access.rs",
            "memoswishd/src/learning_controls.rs",
        ]
        .iter()
        .any(|suffix| source.path.ends_with(suffix))
        {
            for item in &source.syntax.items {
                if let syn::Item::Struct(item) = item {
                    let attrs = item.attrs.iter().map(ast::text).collect::<Vec<_>>().join(" ");
                    if attrs.contains("Serialize") || attrs.contains("Deserialize") {
                        adapters.insert(format!("{}::{}", source.path, item.ident), ast::text(&item.fields));
                    }
                }
            }
        }
    }
    assert!(!types.is_empty() && !paths.is_empty() && !adapters.is_empty());
    json!({"protocol_types": types, "adapter_types": adapters, "routes": paths})
}

#[test]
fn compatibility_inventory_matches_all_public_types_routes_and_adapter_fields() {
    let root = super::root();
    let actual = inventory(&root);
    crate::test_environment::reject_legacy_environment();
    if std::env::var_os("MEMOSWISH_COMPAT_INVENTORY_WRITE").is_some() {
        println!("MEMOSWISH_COMPAT_INVENTORY={}", serde_json::to_string(&actual).unwrap());
        return;
    }
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("compatibility/coverage.json")).unwrap()).unwrap();
    assert_eq!(
        actual, expected,
        "unregistered or stale public boundary; classify and review before explicitly regenerating coverage"
    );
}

#[test]
fn compatibility_nested_content_variants_are_exercised() {
    let schemas: Vec<Value> =
        memoswish_protocol::all_schemas().into_iter().map(|(_, s)| serde_json::to_value(s).unwrap()).collect();
    let blocks = serde_json::to_value(memoswish_protocol::examples::sample_rich_card()).unwrap();
    let tags: BTreeSet<_> = ["front", "back"]
        .into_iter()
        .flat_map(|face| blocks[face]["blocks"].as_array().unwrap().iter())
        .map(|block| block["type"].as_str().unwrap().to_owned())
        .collect();
    let schema = schemas.iter().find(|s| s["title"] == "Card").unwrap();
    let variants: BTreeSet<_> = schema["$defs"]["ContentBlock"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|variant| variant["properties"]["type"]["const"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(tags, variants, "ContentBlock fixture must exercise every nested union variant");
}
