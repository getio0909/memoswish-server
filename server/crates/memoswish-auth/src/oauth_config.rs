//! 授权服务器配置；无 MCP OAuth 能力时仅解析并拒绝启用。
use memoswish_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use url::Url;
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub issuer: String,
    pub public_base_url: String,
    pub mcp_resource: String,
    pub dynamic_registration: bool,
    pub pre_registered_clients: Vec<PreRegisteredClient>,
    pub authorization_code_ttl_secs: i64,
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
}
impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            public_base_url: String::new(),
            mcp_resource: String::new(),
            dynamic_registration: true,
            pre_registered_clients: Vec::new(),
            authorization_code_ttl_secs: 120,
            access_token_ttl_secs: 600,
            refresh_token_ttl_secs: 2592000,
        }
    }
}
impl OAuthConfig {
    pub fn validate(&self) -> CoreResult<()> {
        for s in [&self.issuer, &self.public_base_url, &self.mcp_resource] {
            let u = Url::parse(s).map_err(|_| CoreError::invalid("invalid OAuth public URL"))?;
            if u.scheme() != "https"
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.query().is_some()
                || u.fragment().is_some()
                || u.as_str().trim_end_matches('/') != s.trim_end_matches('/')
            {
                return Err(CoreError::invalid(
                    "OAuth public URLs must be canonical HTTPS without credentials, query or fragment",
                ));
            }
        }
        // 此切片只支持根路径部署；拒绝无法正确发现的反向代理路径前缀。
        let base = Url::parse(&self.public_base_url).map_err(|_| CoreError::invalid("invalid OAuth base"))?;
        if base.path() != "/"
            || self.issuer != self.public_base_url
            || self.mcp_resource != format!("{}/mcp", self.public_base_url.trim_end_matches('/'))
        {
            return Err(CoreError::invalid(
                "OAuth issuer/base must be identical origin URLs ; resource must be base + /mcp",
            ));
        }
        if !(30..=300).contains(&self.authorization_code_ttl_secs)
            || !(60..=3600).contains(&self.access_token_ttl_secs)
            || !(600..=2592000).contains(&self.refresh_token_ttl_secs)
            || self.access_token_ttl_secs > self.refresh_token_ttl_secs
        {
            return Err(CoreError::invalid("invalid OAuth token lifetime"));
        }
        if self.pre_registered_clients.len() > 32 {
            return Err(CoreError::invalid("too many pre-registered clients"));
        }
        let mut ids = std::collections::HashSet::new();
        for client in &self.pre_registered_clients {
            if client.client_id.is_empty()
                || client.client_id.len() > 128
                || !client.client_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
                || !ids.insert(&client.client_id)
                || client.client_name.trim().is_empty()
                || client.client_name.len() > 128
                || client.client_name.chars().any(char::is_control)
                || client.redirect_uris.is_empty()
                || client.redirect_uris.len() > 8
            {
                return Err(CoreError::invalid("invalid pre-registered client metadata"));
            }
            #[cfg(feature = "mcp-oauth")]
            {
                for uri in &client.redirect_uris {
                    crate::oauth::validate_redirect(uri)?;
                }
                crate::oauth::scopes(&client.scope)?;
            }
        }
        Ok(())
    }
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.public_base_url.trim_end_matches('/'), path.trim_start_matches('/'))
    }
    pub fn metadata_url(&self) -> String {
        self.endpoint(".well-known/oauth-protected-resource/mcp")
    }
}

/// 管理员可预置公开客户端；元数据文档远程获取不在此切片实现。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreRegisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scope: String,
}

impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig").field("enabled", &self.enabled).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> OAuthConfig {
        OAuthConfig {
            enabled: true,
            issuer: "https://learn.example".into(),
            public_base_url: "https://learn.example".into(),
            mcp_resource: "https://learn.example/mcp".into(),
            ..Default::default()
        }
    }
    #[test]
    fn oauth_configuration_rejects_insecure_or_incoherent_urls_and_lifetimes() {
        let cfg = config();
        assert!(cfg.validate().is_ok());
        for base in [
            "http://learn.example",
            "https://u:p@learn.example",
            "https://learn.example?secret=x",
            "https://learn.example/#fragment",
            "https://learn.example/prefix",
            "https://learn.example//",
            "https://LEARN.example",
        ] {
            let mut c = cfg.clone();
            c.issuer = base.into();
            c.public_base_url = base.into();
            c.mcp_resource = format!("{base}/mcp");
            assert!(c.validate().is_err(), "{base}");
        }
        let mut c = cfg.clone();
        c.issuer = "https://other.example".into();
        assert!(c.validate().is_err());
        let mut c = cfg.clone();
        c.access_token_ttl_secs = 3601;
        assert!(c.validate().is_err());
        let mut c = cfg.clone();
        c.authorization_code_ttl_secs = 301;
        assert!(c.validate().is_err());
        let mut c = cfg;
        c.refresh_token_ttl_secs = i64::MAX;
        assert!(c.validate().is_err());
    }
}
