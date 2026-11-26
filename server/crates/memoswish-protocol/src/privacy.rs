//! 分离通知、条款、年龄资格及各用途的证据，不包含生日或网络标识。
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PrivacyPolicy {
    pub hosted: bool,
    pub notice_version: String,
    pub terms_version: String,
    pub privacy_url: String,
    pub terms_url: String,
    pub allowed_regions: Vec<String>,
    pub purpose_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyRecord {
    pub kind: String,
    pub version: String,
    pub decision: bool,
    pub value: String,
    pub recorded_at: i64,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PrivacyState {
    pub revision: i64,
    pub account_records: Vec<PrivacyRecord>,
    pub purpose_records: Vec<PrivacyRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyUpdate {
    pub expected_revision: i64,
    pub kind: String,
    pub version: String,
    pub decision: bool,
    #[serde(default)]
    pub value: String,
}
