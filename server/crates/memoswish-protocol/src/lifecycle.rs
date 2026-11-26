//! 显式生命周期确认及按归属分离的导出载荷。

use crate::{AccountProfile, LinkedIdentity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 离开及删除工作区都必须明确确认当前目标。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfirmation {
    pub confirmed_tenant_id: String,
}

/// 确认账户及恰好所有独占工作区；不自动扩大删除范围。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseAccountRequest {
    pub confirmed_user_id: String,
    pub confirmed_exclusive_workspaces: Vec<String>,
}

/// 接任者必须是工作区现有非 owner 成员。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransferOwnershipRequest {
    pub successor_user_id: String,
}

/// 导出段采用列白名单，禁止把存储凭据实体直接序列化。
pub type ExportRows = BTreeMap<String, Vec<serde_json::Value>>;

/// 每个工作区只包含调用者个人学习历史及授权元数据。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PersonalWorkspaceExport {
    pub tenant_id: String,
    pub role: String,
    pub exclusive: bool,
    pub data: ExportRows,
}

/// 全局个人导出不包含工作区共享内容、他人记录或 feed 页回执。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PersonalAccountExport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privacy_records: Vec<serde_json::Value>,
    pub account: AccountProfile,
    pub identities: Vec<LinkedIdentity>,
    pub workspaces: Vec<PersonalWorkspaceExport>,
    pub session_metadata: Vec<serde_json::Value>,
    pub exported_at: String,
}

/// 工作区资产保留旧版十六进制格式。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExportAsset {
    pub key: String,
    pub mime: String,
    pub encoding: String,
    pub data: String,
}

/// 工作区导出仅含共享可读材料及允许公开的工作区元数据。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkspaceExport {
    pub tenant_id: String,
    pub data: ExportRows,
    pub assets: Vec<ExportAsset>,
    pub exported_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn destructive_requests_never_default_missing_or_malformed_confirmations() {
        for value in [
            json!({}),
            json!({"confirmed_tenant_id":null}),
            json!({"confirmed_tenant_id":42}),
            json!({"confirmed_tenant_id":"a","extra":true}),
        ] {
            assert!(serde_json::from_value::<WorkspaceConfirmation>(value).is_err());
        }
        for value in [
            json!({}),
            json!({"confirmed_user_id":"u"}),
            json!({"confirmed_user_id":"u","confirmed_exclusive_workspaces":null}),
            json!({"confirmed_user_id":"u","confirmed_exclusive_workspaces":[4]}),
        ] {
            assert!(serde_json::from_value::<CloseAccountRequest>(value).is_err());
        }
        let close = CloseAccountRequest {
            confirmed_user_id: "u".into(),
            confirmed_exclusive_workspaces: vec!["a".into(), "b".into()],
        };
        assert_eq!(
            serde_json::from_value::<CloseAccountRequest>(serde_json::to_value(&close).unwrap()).unwrap(),
            close
        );
        assert!(serde_json::from_value::<TransferOwnershipRequest>(json!({})).is_err());
    }
}
