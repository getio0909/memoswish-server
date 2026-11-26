//! 解释预算接入统一预检；无效范围、未知键和凭据类型均不能触发安装副作用。
use super::*;

#[tokio::test]
async fn explanation_budget_ranges_are_validated_before_installation() {
    let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let database = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config {
        ai: AiExplainConfig {
            base_url: Some(format!("http://{}", provider.local_addr().unwrap())),
            api_key: Some("P23_CREDENTIAL_SENTINEL".into()),
            budget: Some(crate::tests::explanation_test_policy()),
            ..Default::default()
        },
        ..Default::default()
    };
    Config::parse(&toml::to_string(&config).unwrap()).unwrap().validate().unwrap();
    let mut layered = config.clone();
    layered.apply_object_store_env(&|_| None).unwrap();
    assert_eq!(
        serde_json::to_value(&layered.ai).unwrap(),
        serde_json::to_value(&config.ai).unwrap(),
        "environment layering must preserve every explanation policy key"
    );
    let valid = serde_json::to_value(config.ai.budget.as_ref().unwrap()).unwrap();
    let cases = [
        ("deployment_id", serde_json::json!("P23 CREDENTIAL SENTINEL")),
        ("provider_account", serde_json::json!("")),
        ("pricing_version", serde_json::json!("/private")),
        ("currency", serde_json::json!("usd")),
        ("valid_until_ms", serde_json::json!(0)),
        ("input_rate", serde_json::json!(0)),
        ("output_rate", serde_json::json!(-1)),
        ("rate_denominator", serde_json::json!(0)),
        ("tenant_limit", serde_json::json!(0)),
        ("deployment_limit", serde_json::json!(-1)),
        ("provider_limit", serde_json::json!(0)),
        ("unresolved_limit", serde_json::json!(0)),
        ("cache_entry_bytes", serde_json::json!(16385)),
        ("cache_tenant_bytes", serde_json::json!(1)),
        ("cache_deployment_bytes", serde_json::json!(1)),
        ("cache_ttl_ms", serde_json::json!(86400001)),
        ("input_rate", serde_json::json!(i64::MAX)),
    ];
    for (key, value) in cases {
        let mut policy = valid.clone();
        policy[key] = value;
        let mut cfg = config.clone();
        cfg.ai.budget = Some(serde_json::from_value(policy).unwrap());
        let root = std::env::temp_dir().join(format!("p23-invalid-{}", memoswish_core::ids::new_id()));
        cfg.data_dir = root.clone();
        // SQLite 在最小特性矩阵也可用；全特性下额外证明没有连接数据库。
        if cfg!(feature = "postgres") {
            cfg.database_url =
                Some(format!("postgres://user:P23_CREDENTIAL_SENTINEL@{}/db", database.local_addr().unwrap()));
        }
        let error = crate::Daemon::start(cfg).await.err().expect(key);
        assert!(!root.exists(), "invalid {key} created installation files");
        for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
            assert!(output.contains("explanation budget"), "{key}: {output}");
            assert!(!output.contains("SENTINEL"), "{output}");
        }
    }
    for listener in [&provider, &database] {
        tokio::select! {
            biased;
            _ = listener.accept() => panic!("invalid explanation configuration caused network effects"),
            _ = tokio::task::yield_now() => {}
        }
    }
}

#[test]
fn explanation_config_unknown_keys_and_types_never_echo_credentials() {
    let cfg = Config {
        ai: AiExplainConfig { budget: Some(crate::tests::explanation_test_policy()), ..Default::default() },
        ..Default::default()
    };
    let text = toml::to_string(&cfg).unwrap();
    let mut inputs = vec![
        "[ai]\nP23_CREDENTIAL_SENTINEL='P23_CREDENTIAL_SENTINEL'".to_owned(),
        "[ai]\napi_key={value='P23_CREDENTIAL_SENTINEL'}".to_owned(),
        "[ai]\nbase_url=['P23_CREDENTIAL_SENTINEL']".to_owned(),
        "[ai]\nmodel={value='P23_CREDENTIAL_SENTINEL'}".to_owned(),
        "[ai]\nbudget='P23_CREDENTIAL_SENTINEL'".to_owned(),
        "[ai]\nreasoning_effort='P23_CREDENTIAL_SENTINEL'".to_owned(),
        "[ai]\nreasoning_effort={value='P23_CREDENTIAL_SENTINEL'}".to_owned(),
        "[ai]\nreasoning_effort='low'\nP23_CREDENTIAL_SENTINEL='P23_CREDENTIAL_SENTINEL'".to_owned(),
        text.replace("[ai.budget]", "[ai.budget]\nP23_CREDENTIAL_SENTINEL='P23_CREDENTIAL_SENTINEL'"),
    ];
    for field in serde_json::to_value(cfg.ai.budget.unwrap()).unwrap().as_object().unwrap().keys() {
        let mut value: toml::Value = toml::from_str(&text).unwrap();
        value["ai"]["budget"][field] = toml::Value::Array(vec!["P23_CREDENTIAL_SENTINEL".into()]);
        inputs.push(toml::to_string(&value).unwrap());
    }
    for input in inputs {
        let error = Config::parse(&input).unwrap_err();
        for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
            assert!(!output.contains("P23_CREDENTIAL_SENTINEL"), "{output}");
        }
        assert_eq!(error.chain().count(), 1);
    }
}

#[test]
fn explanation_effort_validates_toml_and_environment_precedence_without_echoing_values() {
    let text = "[ai]\nmodel='gpt-6-luna'\nreasoning_effort='low'";
    let original = Config::parse(text).unwrap();
    assert_eq!(original.ai.reasoning_effort, Some(memoswish_content::explain::ReasoningEffort::Low));
    assert_eq!(Config::parse("[ai]").unwrap().ai.reasoning_effort, None);
    for effort in ["none", "minimal", "low", "medium", "high"] {
        let config = Config::parse_with_env(text, &|key| match key {
            "MEMOSWISH_AI_REASONING_EFFORT" => Some(effort.into()),
            "MEMOSWISH_AI_MODEL" => Some("operator/custom-model".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(serde_json::to_value(config.ai.reasoning_effort).unwrap(), effort);
        assert_eq!(config.ai.model, "operator/custom-model");
        Config::parse(&toml::to_string(&config).unwrap()).unwrap().validate().unwrap();
    }
    let mut layered = original.clone();
    layered.apply_object_store_env(&|_| None).unwrap();
    assert_eq!(layered.ai, original.ai);
    for effort in ["", "LOW", "xhigh", "max", "AI1_CREDENTIAL_SENTINEL"] {
        let error =
            Config::parse_with_env(text, &|key| (key == "MEMOSWISH_AI_REASONING_EFFORT").then(|| effort.into()))
                .unwrap_err();
        for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
            assert!(!output.contains("AI1_CREDENTIAL_SENTINEL"));
        }
        assert_eq!(error.chain().count(), 1);
        assert!(Config::parse(&format!("[ai]\nreasoning_effort='{effort}'")).is_err());
    }
    for invalid in ["0", "true", "['low']", "{low=true}"] {
        assert!(Config::parse(&format!("[ai]\nreasoning_effort={invalid}")).is_err());
    }
}
