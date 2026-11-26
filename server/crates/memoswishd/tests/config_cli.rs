//! CLI 覆盖、非 Unicode 环境与挂载文件注入均在隔离子进程验证。
#![cfg(all(feature = "sqlite", unix))]
use std::{
    ffi::OsString,
    os::unix::{
        ffi::OsStringExt,
        fs::{PermissionsExt, symlink},
    },
    process::Command,
};

fn root() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("s26b-cli-{}", memoswish_core::ids::new_id()));
    std::fs::create_dir(&path).unwrap();
    path
}
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_memoswishd"))
}
#[test]
fn cli_errors_never_echo_credentials_or_create_installation() {
    let root = root();
    let data = root.join("data");
    for mut command in [
        {
            let mut c = command();
            c.args(["--role", "S26B_CREDENTIAL_SENTINEL", "serve"]);
            c
        },
        {
            let mut c = command();
            c.args(["--profile", "horizontal", "--role", "api", "config"]);
            c
        },
        {
            let mut c = command();
            c.args(["--database-url", "S26B_CREDENTIAL_SENTINEL", "config"]);
            c
        },
        {
            let mut c = command();
            c.env("MEMOSWISH_JWT_SECRET", OsString::from_vec(vec![255]));
            c.arg("serve");
            c
        },
        {
            let mut c = command();
            c.env("MEMOSWISH_S26B_CREDENTIAL_SENTINEL", "S26B_CREDENTIAL_SENTINEL");
            c.arg("serve");
            c
        },
    ] {
        command.arg("--data-dir").arg(&data);
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("S26B_CREDENTIAL_SENTINEL"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("S26B_CREDENTIAL_SENTINEL"));
        assert!(!data.exists());
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn database_option_rejection_keeps_startup_tracing_and_installation_secret_free() {
    let root = root();
    let data = root.join("data");
    for level in [None, Some("trace")] {
        for action in ["config", "serve"] {
            for database in [
                "sqlite::memory:?mode=invalid",
                "sqlite::memory:?mode=S26B_CREDENTIAL_SENTINEL",
                "postgres://user:synthetic@127.0.0.1/db?sslmode=invalid",
                "postgres://user:synthetic@127.0.0.1/db?sslmode=S26B_CREDENTIAL_SENTINEL",
                "postgres://user:synthetic@127.0.0.1/db?passwrod=S26B_CREDENTIAL_SENTINEL",
                "postgres://user:synthetic@127.0.0.1/db?S26B_PARAMETER_SENTINEL=S26B_CREDENTIAL_SENTINEL",
            ] {
                let mut child = command();
                child.env_remove("RUST_LOG");
                if let Some(level) = level {
                    child.env("RUST_LOG", level);
                }
                let output =
                    child.args(["--database-url", database, "--data-dir"]).arg(&data).arg(action).output().unwrap();
                assert!(!output.status.success());
                assert!(!output.stderr.is_empty(), "must capture the actual CLI rejection");
                for bytes in [&output.stdout, &output.stderr] {
                    let text = String::from_utf8_lossy(bytes);
                    assert!(!text.contains("S26B_CREDENTIAL_SENTINEL"), "credential leaked: {text}");
                    assert!(!text.contains("S26B_PARAMETER_SENTINEL"), "parameter name leaked: {text}");
                }
                assert!(!data.exists(), "invalid database options must precede lock and key publication");
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn explicit_projected_secret_config_links_are_supported_without_managed_key_creation() {
    let root = root();
    let data = root.join("data");
    let source = root.join("secret.toml");
    let mounted = root.join("config.toml");
    std::fs::write(&source, "jwt_secret='S26B_CREDENTIAL_SENTINEL_WITH_MORE_THAN_32_BYTES'\nseed_demo=false\n")
        .unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&source, &mounted).unwrap();
    for _ in 0..2 {
        let output =
            command().arg("--config").arg(&mounted).arg("--data-dir").arg(&data).arg("config").output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("S26B_CREDENTIAL_SENTINEL"));
        assert!(!data.exists());
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn auth_and_proxy_config_rejection_precedes_effects_and_never_logs_sentinels() {
    let root = root();
    let data = root.join("data");
    let path = root.join("config.toml");
    for config in [
        "[password_work]\nworkers=1",
        "[password_work]\nqueue=65",
        "[password_work]\nmax_bytes=1025",
        "[password_work]\nworkers='S26B_CREDENTIAL_SENTINEL'",
        "[password_work]\nS26B_CREDENTIAL_SENTINEL='S26B_CREDENTIAL_SENTINEL'",
        "[admission]\nauth_failure='open'",
        "[admission]\nmax_keys=4095",
        "[proxy_trust]\ntrusted_peers=['S26B_CREDENTIAL_SENTINEL']",
        "[proxy_trust]\nnormalized_header='S26B_CREDENTIAL_SENTINEL'",
        "[proxy_trust]\nS26B_CREDENTIAL_SENTINEL='S26B_CREDENTIAL_SENTINEL'",
        "[proxy_trust]\ntrusted_peers=['127.0.0.1']",
        "[smtp]\npassword='S26B_CREDENTIAL_SENTINEL'",
    ] {
        std::fs::write(&path, config).unwrap();
        for action in ["config", "serve"] {
            let output = command()
                .env("RUST_LOG", "trace")
                .arg("--config")
                .arg(&path)
                .arg("--data-dir")
                .arg(&data)
                .arg(action)
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(!output.stderr.is_empty());
            for bytes in [&output.stdout, &output.stderr] {
                assert!(!String::from_utf8_lossy(bytes).contains("S26B_CREDENTIAL_SENTINEL"));
            }
            assert!(!data.exists());
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_environment_is_rejected_before_help_config_and_side_effects() {
    let root = root();
    let data = root.join("data");
    for suffix in ["JWT_SECRET", "CONFIG", "TOKEN", "TEST_POSTGRES_URL", "UNKNOWN_OPTION"] {
        for value in [OsString::from(""), OsString::from("RENAME1_SECRET_SENTINEL"), OsString::from_vec(vec![255])] {
            for action in ["--help", "--version", "config", "serve"] {
                let output = command()
                    .env(format!("LEARNTOK_{suffix}"), &value)
                    .env(format!("MEMOSWISH_{suffix}"), "RENAME1_NEW_SECRET_SENTINEL")
                    .args(["--data-dir"])
                    .arg(&data)
                    .arg(action)
                    .output()
                    .unwrap();
                assert!(!output.status.success());
                let text = String::from_utf8_lossy(&output.stderr);
                assert!(text.contains(&format!("MEMOSWISH_{suffix}")), "{text}");
                assert!(!text.contains("SECRET_SENTINEL"));
                assert!(output.stdout.is_empty());
                assert!(!data.exists());
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn renamed_environment_preserves_file_environment_cli_precedence_and_database_fallback() {
    let root = root();
    let file = root.join("config.toml");
    std::fs::write(&file, "bind='127.0.0.1:8001'\nseed_demo=false\n").unwrap();
    let output = command()
        .env("MEMOSWISH_BIND", "127.0.0.1:8002")
        .env("DATABASE_URL", "sqlite::memory:")
        .arg("--config")
        .arg(&file)
        .args(["--bind", "127.0.0.1:8003", "config"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("127.0.0.1:8003"));
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("memoswishd"));
    assert!(help.contains("MEMOSWISH_CONFIG"));
    assert!(!help.contains("LEARNTOK_"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn schema_export_refreshes_only_json_and_preserves_existing_files_on_failure() {
    let dir = root();
    let readme = dir.join("README.md");
    std::fs::write(&readme, b"caller-owned\r\n\xff").unwrap();
    let schemas = dir.join("schemas");
    let fixtures = dir.join("fixtures");
    for sub in [&schemas, &fixtures] {
        std::fs::create_dir(sub).unwrap();
        std::fs::write(sub.join("obsolete.json"), b"old").unwrap();
    }
    let schema = schemas.join("access-summary.schema.json");
    let fixture = fixtures.join("access-summary.json");
    // 阻止第一个目标被替换，验证写入失败前未清空任何一侧。
    std::fs::create_dir(&schema).unwrap();
    std::fs::write(&fixture, b"old fixture").unwrap();
    let export = || command().args(["schema", "export", "--out"]).arg(&dir).output().unwrap();
    assert!(!export().status.success());
    for sub in [&schemas, &fixtures] {
        assert_eq!(std::fs::read(sub.join("obsolete.json")).unwrap(), b"old");
    }
    assert_eq!(std::fs::read(&fixture).unwrap(), b"old fixture");
    std::fs::remove_dir(&schema).unwrap();
    std::fs::write(&schema, b"old schema").unwrap();
    let output = export();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(std::fs::read(&readme).unwrap(), b"caller-owned\r\n\xff");
    assert_eq!(
        std::fs::read(schema).unwrap(),
        include_bytes!("../../../../protocol/schemas/access-summary.schema.json")
    );
    assert_eq!(std::fs::read(fixture).unwrap(), include_bytes!("../../../../protocol/fixtures/access-summary.json"));
    for sub in [&schemas, &fixtures] {
        assert!(!sub.join("obsolete.json").exists());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn effective_secret_placeholders_are_rejected_without_disclosure() {
    let dir = root();
    let file = dir.join("config.toml");
    let data = dir.join("data");
    for (toml, field, value) in [
        ("jwt_secret", "jwt_secret", "replace-with-a-shared-secret-of-32-bytes-or-more"),
        ("jwt_keys.active.secret", "jwt_keys.secret", "replace-with-independent-random-secret"),
        ("object_store.s3.access_key_id", "object_store.s3.access_key_id", "RePlAcE-Me-example"),
        ("object_store.s3.secret_access_key", "object_store.s3.secret_access_key", "replace-me"),
        ("ai.api_key", "ai.api_key", "sk-..."),
        ("oidc.encryption_key", "oidc.encryption_key", "CHANGE-ME-key"),
        ("oidc.encryption_keys.active.secret", "oidc.encryption_keys.secret", "changeme-key"),
    ] {
        std::fs::write(&file, format!("{toml} = '{value}'")).unwrap();
        let output = command().arg("--config").arg(&file).arg("--data-dir").arg(&data).arg("config").output().unwrap();
        assert!(!output.status.success());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(field) && !message.contains(value), "{message}");
        assert!(output.stdout.is_empty() && !data.exists());
    }
    for (alias, field, value) in [
        ("MEMOSWISH_JWT_SECRET", "jwt_secret", "change-me-to-a-long-random-string-at-least-32-bytes"),
        ("MEMOSWISH_S3_ACCESS_KEY_ID", "object_store.s3.access_key_id", "CHANGEME-access"),
        ("MEMOSWISH_S3_SECRET_ACCESS_KEY", "object_store.s3.secret_access_key", "rEpLaCe-WiTh-secret"),
        ("MEMOSWISH_AI_API_KEY", "ai.api_key", "sk-..."),
    ] {
        let output = command().env(alias, value).arg("--data-dir").arg(&data).arg("serve").output().unwrap();
        assert!(!output.status.success());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(field) && !message.contains(value), "{message}");
        assert!(output.stdout.is_empty() && !data.exists());
    }
    for url in [
        "postgres://user:secret@localhost/db",
        "postgres://user:%63hangeme-credential@localhost/db",
        "postgres://localhost/db?password=replace-me-credential",
    ] {
        let output = command().args(["--database-url", url, "config"]).output().unwrap();
        assert!(!output.status.success());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(
            message.contains("database_url.password")
                && !message.contains("changeme")
                && !message.contains("replace-me")
                && !message.contains("secret"),
            "{message}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(feature = "postgres")]
#[test]
fn postgres_cli_validates_only_the_resolved_password_before_startup() {
    let dir = root();
    let data = dir.join("data");
    let pgpass = dir.join("pgpass");
    let url = "postgres://YOUR_USER@localhost:5432/db";
    let placeholder = "change-me-pg-fallback-sentinel";
    let valid = "round-one-fixture-credential";
    let cases = [
        (url, Some(placeholder), valid, false),
        (url, None, placeholder, false),
        (url, Some(valid), placeholder, true),
        (url, None, valid, true),
        ("postgres://YOUR_USER:round-one-fixture-credential@localhost/db", Some(placeholder), placeholder, true),
        ("postgres://YOUR_USER@%2Fvar%2Frun%2Fpostgresql/peer_db", None, placeholder, true),
    ];
    for (url, env_password, file_password, accepted) in cases {
        std::fs::write(&pgpass, format!("localhost:5432:db:YOUR_USER:{file_password}\n")).unwrap();
        std::fs::set_permissions(&pgpass, std::fs::Permissions::from_mode(0o600)).unwrap();
        for action in if accepted { &["config"][..] } else { &["config", "serve"][..] } {
            let mut cmd = command();
            cmd.env("HOME", &dir).env_remove("PGPASSWORD").env("PGPASSFILE", &pgpass).env("RUST_LOG", "trace");
            if let Some(password) = env_password {
                cmd.env("PGPASSWORD", password);
            }
            let output = cmd.arg("--data-dir").arg(&data).args(["--database-url", url, action]).output().unwrap();
            assert_eq!(output.status.success(), accepted);
            for bytes in [&output.stdout, &output.stderr] {
                let text = String::from_utf8_lossy(bytes);
                assert!(!text.contains(placeholder) && !text.contains(valid));
            }
            if !accepted {
                assert!(String::from_utf8_lossy(&output.stderr).contains("database_url.password"));
                assert!(output.stdout.is_empty());
            }
            assert!(!data.exists());
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(all(feature = "postgres", feature = "s3", feature = "redis"))]
#[test]
fn shipped_config_examples_validate_with_only_the_documented_secrets() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
    for file in std::fs::read_dir(dir).unwrap() {
        let file = file.unwrap().path();
        if !file.to_string_lossy().ends_with(".example.toml") {
            continue;
        }
        let mut child = command();
        child.arg("--config").arg(&file).arg("config");
        for key in ["MEMOSWISH_JWT_SECRET", "MEMOSWISH_S3_ACCESS_KEY_ID", "MEMOSWISH_S3_SECRET_ACCESS_KEY"] {
            child.env_remove(key);
        }
        if file.ends_with("memoswishd.horizontal.example.toml") {
            let output = child.output().unwrap();
            assert!(!output.status.success());
            let message = String::from_utf8_lossy(&output.stderr);
            assert!(message.contains("credentials") || message.contains("access_key"), "{message}");
            child
                .env("MEMOSWISH_S3_ACCESS_KEY_ID", "fixture-access")
                .env("MEMOSWISH_S3_SECRET_ACCESS_KEY", "fixture-secret");
            let output = child.output().unwrap();
            assert!(!output.status.success() && String::from_utf8_lossy(&output.stderr).contains("jwt_secret"));
            child.env("MEMOSWISH_JWT_SECRET", "fixture-shared-jwt-signing-secret-of-32-bytes");
        }
        let output = child.output().unwrap();
        assert!(output.status.success(), "{file:?}: {}", String::from_utf8_lossy(&output.stderr));
    }
}
