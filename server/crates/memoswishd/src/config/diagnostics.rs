//! TOML 错误仅保留结构诊断，禁止回显错误值或源码。

pub(super) fn sanitized(text: &str, error: serde_path_to_error::Error<toml::de::Error>) -> anyhow::Error {
    let offset = error.inner().span().map_or(0, |span| span.start).min(text.len());
    let before = &text.as_bytes()[..offset];
    let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
    let column = offset - before.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1) + 1;
    // 只输出分类后的结构信息，原始错误及源码不能进入错误链。
    let reason = safe_reason(error.inner().message());
    let mut path = String::new();
    let mut dynamic = false;
    for segment in error.path() {
        match segment {
            serde_path_to_error::Segment::Seq { index } => path.push_str(&format!("[{index}]")),
            serde_path_to_error::Segment::Map { key } => {
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(if dynamic { "<key>" } else { key });
                dynamic = matches!(key.as_str(), "jwt_keys" | "encryption_keys" | "purpose_versions");
            }
            _ => {}
        }
    }
    if path.is_empty() {
        path.push('.');
    }
    anyhow::anyhow!("invalid config: {reason} at line {line}, column {column}, key {path}")
}

fn field_name(value: &str) -> Option<&str> {
    // 字段名可定位配置错误，但不能把任意自定义错误文本当字段名输出。
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')).then_some(value)
}

fn safe_reason(message: &str) -> String {
    if let Some(field) = message.strip_prefix("missing field `").and_then(|s| s.strip_suffix('`')).and_then(field_name)
    {
        return format!("missing field `{field}`");
    }
    if message.starts_with("unknown field `") {
        let field =
            message.strip_prefix("unknown field `").and_then(|s| s.split_once("`,")).and_then(|(s, _)| field_name(s));
        return match field {
            Some(field) => format!("unknown field `{field}`"),
            None => "unknown field".into(),
        };
    }
    if message.starts_with("invalid type:")
        || message.starts_with("invalid value:")
        || message.starts_with("unknown variant ")
    {
        // expected 的原始字符串也不直接输出，只接受已知的静态类型描述。
        let expected = message.rsplit_once(", expected ").map(|(_, expected)| expected);
        let safe = match expected {
            Some("a string") => "a string",
            Some("path string") => "a filesystem path string",
            Some("a boolean") => "a boolean",
            Some("u8") => "u8",
            Some("u16") => "u16",
            Some("u32") => "u32",
            Some("u64") => "u64",
            Some("i8") => "i8",
            Some("i16") => "i16",
            Some("i32") => "i32",
            Some("i64") => "i64",
            Some("f32") => "f32",
            Some("f64") => "f64",
            Some("a sequence") => "an array",
            Some("a map") => "a table",
            Some("string or map") => "a string or table",
            Some("`single_user` or `multi_tenant`" | "one of `single_user`, `multi_tenant`") => {
                "single_user or multi_tenant"
            }
            Some(value) if value.starts_with("struct ") => "a table",
            _ => "a valid value for this field",
        };
        return format!("type mismatch: expected {safe}");
    }
    // 语法错误可能包含重复键等输入片段，因此只输出固定的原因分类。
    if message.starts_with("duplicate key") {
        "syntax: duplicate key".into()
    } else if message.contains("expected newline") {
        "syntax: expected newline or comment after value".into()
    } else if message.contains("expected `=`") {
        "syntax: expected `=` after key".into()
    } else if message.contains("expected `]`") {
        "syntax: expected closing `]` for array or table".into()
    } else if message.contains("expected `}`") {
        "syntax: expected closing `}` for inline table".into()
    } else if message.contains("string") {
        "syntax: invalid or unterminated string".into()
    } else {
        "syntax: invalid TOML; check delimiters, keys and value syntax".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn assert_diagnostic(error: anyhow::Error, expected: &[&str]) {
        for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
            assert!(!output.contains("synthetic-private-secret"), "{output}");
            assert!(!output.contains(" = "), "source excerpts must not be printed: {output}");
            for part in expected {
                assert!(output.contains(part), "missing {part:?}: {output}");
            }
        }
        assert_eq!(error.chain().count(), 1, "raw errors must not enter the source chain");
    }

    #[test]
    fn config_diagnostics_preserve_missing_fields_expected_types_and_locations() {
        for (text, expected) in [
            (
                "jwt_secret = 'synthetic-private-secret'\n[[oauth.pre_registered_clients]]\nclient_id = 'synthetic-private-secret'\nredirect_uris = []\nscope = 'synthetic-private-secret'\n",
                vec!["missing field `client_name`", "key oauth.pre_registered_clients[0]", "line 2, column 1"],
            ),
            (
                "[object_store.s3]\nsecret_access_key = 'synthetic-private-secret',\n",
                vec!["syntax:", "expected newline", "line 2, column 47", "key ."],
            ),
            (
                "[object_store.s3]\npresign_ttl_secs = 'synthetic-private-secret'\n",
                vec!["type mismatch: expected u64", "key object_store.s3.presign_ttl_secs", "line 2, column 20"],
            ),
            (
                "seed_demo = 'synthetic-private-secret'\n",
                vec!["type mismatch: expected a boolean", "key seed_demo", "line 1, column 13"],
            ),
            (
                "mode = 'synthetic-private-secret'\n",
                vec!["type mismatch: expected single_user or multi_tenant", "key mode", "line 1, column 8"],
            ),
            (
                "[object_store.s3]\nsecret_access_key = { value = 'synthetic-private-secret' }\n",
                vec!["type mismatch: expected a string", "key object_store.s3.secret_access_key", "line 2, column 21"],
            ),
            (
                "cors_origins = 'synthetic-private-secret'\n",
                vec!["type mismatch: expected an array", "key cors_origins", "line 1, column 16"],
            ),
        ] {
            assert_diagnostic(Config::parse(text).unwrap_err(), &expected);
        }
    }

    #[test]
    fn unknown_field_diagnostics_name_the_field_without_its_value() {
        // 配置加载另行追踪未知字段；此严格结构覆盖 Serde 的结构诊断路径。
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            #[serde(rename = "client_name")]
            _client_name: String,
        }
        let text = "client_nmae = 'synthetic-private-secret'\n";
        let error = serde_path_to_error::deserialize::<_, Strict>(toml::Deserializer::new(text)).unwrap_err();
        assert_diagnostic(
            sanitized(text, error),
            &["unknown field `client_nmae`", "line 1, column 1", "key client_nmae"],
        );
    }

    #[test]
    fn diagnostic_classification_never_copies_supplied_values() {
        for message in [
            "invalid type: string \"private-secret, expected a string\", expected u64",
            "unknown variant `private-secret, expected a string`, expected `single_user` or `multi_tenant`",
            "duplicate key `private-secret` in table `object_store.s3`",
            "unknown field `typo`, expected one of `client_id`, `client_name`",
        ] {
            let reason = safe_reason(message);
            assert!(!reason.contains("private-secret"), "{reason}");
        }
        assert_eq!(safe_reason("unknown field `typo`, expected `client_name`"), "unknown field `typo`");
        assert_eq!(safe_reason("invalid type: string \"private-secret\", expected u64"), "type mismatch: expected u64");
    }
}
