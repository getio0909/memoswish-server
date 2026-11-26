//! 管理员固定的身份提供者配置；解析配置不会启用登录路由。
use memoswish_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcConfig {
    pub enabled: bool,
    pub public_base_url: String,
    /// 32 字节 base64url 密钥，所有副本相同，用于加密 PKCE 与上游撤销凭据。
    pub encryption_key: String,
    pub encryption_key_id: String,
    pub encryption_keys: std::collections::BTreeMap<String, crate::token::VerificationKey>,
    pub legacy_encryption_until: Option<i64>,
    pub return_uris: Vec<String>,
    pub providers: Vec<OidcProvider>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcProvider {
    pub id: String,
    pub name: String,
    /// google / apple / generic。
    pub kind: String,
    pub issuer: String,
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_auth_method: String,
    pub native_client_ids: Vec<String>,
    /// discovery 中所有服务端端点必须属于显式主机白名单。
    pub allowed_hosts: Vec<String>,
    /// 仅管理员显式启用时允许私网身份基础设施和 HTTP。
    pub allow_private_network: bool,
    pub algorithms: Vec<String>,
    pub apple_team_id: String,
    pub apple_key_id: String,
    pub apple_private_key: String,
}
impl Default for OidcProvider {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            kind: "generic".into(),
            issuer: String::new(),
            discovery_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            token_auth_method: "client_secret_post".into(),
            native_client_ids: vec![],
            allowed_hosts: vec![],
            allow_private_network: false,
            algorithms: vec!["RS256".into()],
            apple_team_id: String::new(),
            apple_key_id: String::new(),
            apple_private_key: String::new(),
        }
    }
}
impl OidcConfig {
    pub fn validate(&self) -> CoreResult<()> {
        let base = url::Url::parse(&self.public_base_url).map_err(|_| CoreError::invalid("invalid OIDC public URL"))?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(CoreError::invalid("OIDC public URL must be an HTTPS root"));
        }
        if self.providers.is_empty()
            || self.providers.len() > 16
            || self.return_uris.is_empty()
            || self.return_uris.len() > 16
        {
            return Err(CoreError::invalid("OIDC requires bounded providers and return URIs"));
        }
        let mut ids = std::collections::HashSet::new();
        for p in &self.providers {
            if p.id.is_empty()
                || p.id.len() > 64
                || !p.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || !ids.insert(&p.id)
                || p.name.len() > 128
                || p.client_id.is_empty()
                || p.native_client_ids.len() > 16
                || !["none", "client_secret_post", "client_secret_basic"].contains(&p.token_auth_method.as_str())
                || (p.kind == "apple" && p.token_auth_method != "client_secret_post")
                || !["google", "apple", "generic"].contains(&p.kind.as_str())
                || p.algorithms.is_empty()
                || p.algorithms.iter().any(|a| !["RS256", "ES256"].contains(&a.as_str()))
            {
                return Err(CoreError::invalid("invalid OIDC provider profile"));
            }
            p.validate_url(&p.issuer)?;
            p.validate_url(&p.discovery_url)?;
            if (p.kind == "google" && p.issuer != "https://accounts.google.com")
                || (p.kind == "apple" && p.issuer != "https://appleid.apple.com")
            {
                return Err(CoreError::invalid("built-in provider issuer mismatch"));
            }
            if p.kind == "apple"
                && (p.apple_team_id.is_empty()
                    || p.apple_key_id.is_empty()
                    || p.apple_private_key.is_empty()
                    || p.algorithms != ["RS256"])
            {
                return Err(CoreError::invalid("Apple requires signing credentials and RS256 ID tokens"));
            }
        }
        #[cfg(feature = "oidc")]
        for provider in self.providers.iter().filter(|p| p.kind == "apple") {
            crate::oidc::apple_client_secret(provider, 0)
                .map_err(|_| CoreError::invalid("invalid Apple signing credentials"))?;
        }
        for uri in &self.return_uris {
            let u = url::Url::parse(uri).map_err(|_| CoreError::invalid("invalid OIDC return URI"))?;
            if uri.len() > 2048
                || u.fragment().is_some()
                || u.query().is_some()
                || !u.username().is_empty()
                || u.password().is_some()
                || !(u.scheme() == "https" && u.host_str().is_some()
                    || u.scheme().contains('.')
                        && u.host_str().is_none()
                        && !u.has_authority()
                        && u.path().starts_with('/')
                        && !u.path().starts_with("//"))
            {
                return Err(CoreError::invalid("unsafe OIDC return URI"));
            }
        }
        Ok(())
    }
    pub fn redacted(&self) -> Self {
        let mut c = self.clone();
        c.encryption_key = "***".into();
        for k in c.encryption_keys.values_mut() {
            k.secret = "***".into();
        }
        // 即使配置尚未启用或无效，也不打印可能夹带凭据的 URL。
        c.public_base_url = "***".into();
        c.return_uris = vec![];
        for p in &mut c.providers {
            p.client_secret = "***".into();
            p.apple_private_key = "***".into();
            p.issuer = "***".into();
            p.discovery_url = "***".into();
        }
        c
    }
}
impl OidcProvider {
    pub fn validate_url(&self, value: &str) -> CoreResult<url::Url> {
        let u = url::Url::parse(value).map_err(|_| CoreError::invalid("invalid configured OIDC endpoint"))?;
        if !(u.scheme() == "https" || self.allow_private_network && u.scheme() == "http")
            || !self.allowed_hosts.iter().any(|h| Some(h.as_str()) == u.host_str())
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
            || u.query().is_some()
        {
            return Err(CoreError::invalid("OIDC endpoint violates configured network policy"));
        }
        Ok(u)
    }
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("enabled", &self.enabled)
            .field("providers", &self.providers.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OidcProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcProvider").finish_non_exhaustive()
    }
}
