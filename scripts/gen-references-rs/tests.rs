use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use syn::visit::Visit;

use super::{ast, check_documents, configuration, mcp, render, routes};

#[test]
fn references_are_deterministic() {
    let first = render();
    assert_eq!(first, render());
    assert!(first.values().all(|document| !document.contains(REFERENCE_SECRET_SENTINEL)));
}

struct TemporaryDirectory(std::path::PathBuf);
impl TemporaryDirectory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "memoswish-refs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn drift_and_missing_documents_fail_without_rewriting() {
    let directory = TemporaryDirectory::new();
    let expected = BTreeMap::from([("reference.md".into(), "expected\n".into())]);
    assert!(check_documents(&directory.0, &expected).is_err());
    let path = directory.0.join("reference.md");
    std::fs::write(&path, "stale\n").unwrap();
    assert!(check_documents(&directory.0, &expected).unwrap_err().contains("has drifted"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "stale\n");
    std::fs::write(&path, "expected\n").unwrap();
    assert_eq!(check_documents(&directory.0, &expected), Ok(()));
}

const REFERENCE_SECRET_SENTINEL: &str = "SYNTHETIC_REF_SECRET_DO_NOT_PUBLISH";

#[test]
fn synthetic_secrets_are_never_rendered() {
    let sentinel = REFERENCE_SECRET_SENTINEL;
    for key in [
        "smtp.password",
        "smtp.username",
        "jwt_secret",
        "admission.redis_url",
        "database_url",
        "ai.api_key",
        "tts.http[].api_key",
        "object_store.s3.access_key_id",
        "object_store.s3.secret_access_key",
        "oidc.encryption_key",
        "oidc.providers[].client_secret",
        "oidc.providers[].apple_private_key",
    ] {
        let rendered = configuration::safe_default(key, &json!(sentinel));
        assert!(!rendered.contains(sentinel), "secret escaped redaction for {key}");
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "generated_refs::tests::references_are_deterministic", "--nocapture"])
        .env("MEMOSWISH_CONFIG", "/nonexistent-synthetic-config.toml")
        .env("MEMOSWISH_JWT_SECRET", sentinel)
        .env("MEMOSWISH_DATABASE_URL", sentinel)
        .env("DATABASE_URL", sentinel)
        .env("MEMOSWISH_AI_API_KEY", sentinel)
        .env("MEMOSWISH_OIDC_ENCRYPTION_KEY", sentinel)
        .env("MEMOSWISH_OIDC_PROVIDERS_JSON", sentinel)
        .env("MEMOSWISH_S3_SECRET_ACCESS_KEY", sentinel)
        .env("MEMOSWISH_BLESS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "reference generation read live configuration: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(sentinel) && !String::from_utf8_lossy(&output.stderr).contains(sentinel));
    let summary = stdout
        .lines()
        .find(|line| line.starts_with("test result: ok. 1 passed;"))
        .expect("reference generator child did not pass the selected test");
    println!("Reference generator child: {summary}");
}

#[test]
fn route_parser_tracks_methods_layers_conditions_and_head_override() {
    let source = syn::parse_file(
        r#"
        /// 参考条件：feature synthetic。
        fn router() {
            Router::new().route("/sample", get(read).head(explicit_head).post(write).layer(body_limit()));
            if enabled { Router::new().route("/conditional", delete(remove)); }
        }
        #[cfg(test)] mod tests { fn ignored() { Router::new().route("/fixture", get(fixture)); } }
    "#,
    )
    .unwrap();
    let mut inventory = routes::Inventory::new("fixture.rs");
    inventory.visit_file(&source);
    assert_eq!(inventory.routes.len(), 4);
    assert!(
        inventory.routes.iter().any(|r| r.path == "/sample" && r.methods == "HEAD" && r.handler == "explicit_head")
    );
    assert!(inventory.routes.iter().any(|r| r.path == "/conditional" && r.condition.contains("if enabled")));
    assert!(inventory.routes.iter().all(|r| r.condition.contains("feature synthetic")));
}

#[test]
fn unsupported_routing_forms_fail_closed() {
    for expression in [
        r#"Router::new().route(dynamic, get(read))"#,
        r#"Router::new().nest("/v2", nested)"#,
        r#"Router::new().route("/x", any(handler))"#,
    ] {
        let source = syn::parse_file(&format!("fn router() {{ {expression}; }}")).unwrap();
        assert!(std::panic::catch_unwind(|| routes::Inventory::new("fixture.rs").visit_file(&source)).is_err());
    }
}

#[test]
fn catalog_dispatch_and_policy_must_be_complete() {
    let catalog = BTreeSet::from(["existing".into(), "new_tool".into()]);
    let old = BTreeSet::from(["existing".into()]);
    assert!(std::panic::catch_unwind(|| mcp::assert_complete(&catalog, &old, &catalog)).is_err());
    assert!(std::panic::catch_unwind(|| mcp::assert_complete(&catalog, &catalog, &old)).is_err());
}

#[test]
fn conditional_permissions_preserve_preview_tts_and_bgm_boundaries() {
    for (name, args, expected) in [
        ("card_upsert", json!({"auto_tts": false}), "content:write"),
        ("card_upsert", json!({"auto_tts": false, "bgm": {}}), "content:read content:write"),
        ("card_upsert", json!({}), "content:read content:write tts:generate"),
        ("deck_import", json!({"auto_tts": false}), "content:write"),
        ("material_slice", json!({}), "content:read"),
        ("material_slice", json!({"commit": true, "auto_tts": false}), "content:read content:write"),
        ("material_slice", json!({"commit": true}), "content:read content:write tts:generate"),
        ("deck_import_apkg", json!({}), "content:write media:write"),
        ("tts_engines", json!({}), "media:read"),
    ] {
        let permissions = memoswish_mcp::http::required_permissions(&json!({
            "method": "tools/call", "params": {"name": name, "arguments": args}
        }));
        let mut actual: Vec<_> = permissions.iter().map(|p| p.as_scope()).collect();
        actual.sort();
        assert_eq!(actual.join(" "), expected, "conditional permission drift for {name}");
    }
}

#[test]
fn statistics_resource_includes_descriptor_and_read_permission() {
    let sources = ast::Sources::load(&super::root());
    let reference = mcp::render(&sources);
    assert!(reference.contains(
        "| `memoswish://stats` | Learning Statistics | `application/json` | Global FSRS-6 learning statistics (total, seen, due, starred, average retrievability, exposures). | feed:read |"
    ));
}

#[test]
fn nested_resource_descriptor_changes_fail_drift_without_rewriting() {
    let mut sources = ast::Sources::load(&super::root());
    let original = ast::text(&sources.file("memoswish-mcp/src/server.rs").syntax);
    let directory = TemporaryDirectory::new();
    let documents = directory.0.as_path();
    let committed = mcp::render(&sources).into_bytes();
    std::fs::write(documents.join("mcp-tools.md"), &committed).unwrap();
    for (before, after) in [
        ("Learning Statistics", "Learning Statistics drift regression"),
        (
            "Global FSRS-6 learning statistics (total, seen, due, starred, average retrievability, exposures).",
            "Synthetic statistics description for drift regression.",
        ),
        ("\"memoswish://stats\"", "\"memoswish://stats-drift-regression\""),
    ] {
        assert!(original.contains(before), "missing descriptor mutation target");
        let source = sources.files.iter_mut().find(|s| s.path.ends_with("memoswish-mcp/src/server.rs")).unwrap();
        source.syntax = syn::parse_file(&original.replacen(before, after, 1)).unwrap();
        let expected = BTreeMap::from([("mcp-tools.md".into(), mcp::render(&sources))]);
        assert!(check_documents(documents, &expected).unwrap_err().contains("mcp-tools.md has drifted"));
        assert_eq!(std::fs::read(documents.join("mcp-tools.md")).unwrap(), committed);
    }
}

#[test]
fn environment_aliases_and_fallbacks_are_extracted_from_assignments() {
    let source = syn::parse_file(
        r#"
        fn overrides() {
            if let Some(v) = var("PRIMARY").or_else(|| var("FALLBACK")) { self.value = v; }
            let s = &mut self.object_store.s3;
            for (key, target) in [("MEMOSWISH_NEW", &mut s.region)] { *target = var(key); }
        }
    "#,
    )
    .unwrap();
    let mut env = configuration::Environment::default();
    env.visit_file(&source);
    assert_eq!(env.mappings["PRIMARY"], "value");
    assert_eq!(env.mappings["FALLBACK"], "value");
    assert_eq!(env.mappings["MEMOSWISH_NEW"], "object_store.s3.region");
}

#[test]
fn configuration_field_and_route_changes_change_the_references() {
    let mut sources = ast::Sources::load(&super::root());
    let original_config = configuration::render(&sources);
    let original_routes = routes::render(&sources);
    let source = sources.files.iter_mut().find(|s| s.path.ends_with("memoswishd/src/config.rs")).unwrap();
    for item in &mut source.syntax.items {
        if let syn::Item::Struct(item) = item
            && item.ident == "Config"
        {
            item.fields.iter_mut().find(|f| f.ident.as_ref().is_some_and(|v| v == "bind")).unwrap().ident =
                Some(syn::parse_str("new_bind_key").unwrap());
        }
    }
    // 字段改名也必须更新环境映射，否则提取阶段立即拒绝不一致。
    assert!(std::panic::catch_unwind(|| configuration::render(&sources)).is_err());
    assert!(!original_config.contains("new_bind_key"));
    let source = sources.files.iter_mut().find(|s| s.path.ends_with("memoswishd/src/api.rs")).unwrap();
    source.syntax.items.push(syn::parse_quote!(
        fn new_router() {
            Router::new().route("/new-regression-route", get(new_handler));
        }
    ));
    assert_ne!(original_routes, routes::render(&sources));
}

#[test]
fn sdk_prompt_handler_does_not_replace_product_prompt_catalog_extraction() {
    let mut sources = ast::Sources::load(&super::root());
    let expected = mcp::render(&sources);
    let source = sources.files.iter_mut().find(|source| source.path.ends_with("memoswish-mcp/src/server.rs")).unwrap();
    let extra = syn::parse_file(
        r#"impl AnotherHandler { fn get_prompt() { match name { "synthetic_sdk_prompt" => (), _ => () } } }"#,
    )
    .unwrap();
    source.syntax.items.extend(extra.items);
    assert_eq!(mcp::render(&sources), expected);
}

#[test]
fn downstream_extension_mount_is_narrow_and_does_not_hide_core_routes() {
    const RUNTIME: &str = "server/crates/memoswishd/src/runtime.rs";
    let source = syn::parse_file(
        r#"fn serve() {
            app = app.nest("/extensions", routes);
            app = app.route("/core-still-inventoried", get(read));
        }"#,
    )
    .unwrap();
    let mut inventory = routes::Inventory::new(RUNTIME);
    inventory.visit_file(&source);
    assert_eq!(inventory.routes.len(), 2);
    assert!(inventory.routes.iter().all(|route| route.path == "/core-still-inventoried"));
    assert!(inventory.routes.iter().any(|route| route.methods == "GET" && route.handler == "read"));
    assert!(inventory.routes.iter().any(|route| route.methods == "HEAD"));
    for (file, expression) in [
        ("fixture.rs", r#"app.nest("/extensions", routes)"#),
        (RUNTIME, r#"app.nest("/v1", routes)"#),
        (RUNTIME, r#"app.nest(prefix, routes)"#),
        (RUNTIME, r#"app.nest("/extensions/", routes)"#),
        (RUNTIME, r#"app.nest("/extensions", other_routes)"#),
        (RUNTIME, r#"app.nest("/extensions", Router::new().route("/hidden", get(read)))"#),
        (RUNTIME, r#"app.nest_service("/extensions", routes)"#),
        (RUNTIME, r#"app.route_service("/extensions", routes)"#),
        (RUNTIME, r#"other.nest("/extensions", routes)"#),
        (RUNTIME, r#"app.nest("/extensions", routes, extra)"#),
        (RUNTIME, r#"app.nest("/extensions", routes).nest("/hidden", other_routes)"#),
    ] {
        let source = syn::parse_file(&format!("fn serve() {{ {expression}; }}")).unwrap();
        assert!(std::panic::catch_unwind(|| routes::Inventory::new(file).visit_file(&source)).is_err());
    }
}
