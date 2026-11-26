//! JWT 与 API Token 编解码。

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use memoswish_core::ids::sha256_hex;
use memoswish_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

/// API Token 明文前缀，便于密钥扫描工具识别。
pub const API_TOKEN_PREFIX: &str = "ltk_";
/// JWT 签发者。
pub const JWT_ISSUER: &str = "learntokd";

/// JWT 载荷。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub profile: String,
    pub membership_generation: i64,
    /// 用户 ID。
    pub sub: String,
    /// 租户 ID。
    pub tid: String,
    /// 角色。
    pub role: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub generation: i64,
}

/// HS256 JWT 编解码器。
#[derive(Clone)]
pub struct JwtCodec {
    enc: EncodingKey,
    dec: DecodingKey,
    ttl_secs: u64,
    key_id: Option<String>,
    retained: std::collections::BTreeMap<String, VerificationKey>,
    legacy_until: Option<i64>,
}

impl JwtCodec {
    pub fn new(secret: &[u8], ttl_secs: u64) -> CoreResult<Self> {
        if secret.len() < 32 {
            return Err(CoreError::invalid("jwt secret must be at least 32 bytes"));
        }
        Ok(Self {
            enc: EncodingKey::from_secret(secret),
            dec: DecodingKey::from_secret(secret),
            ttl_secs,
            key_id: None,
            retained: Default::default(),
            legacy_until: None,
        })
    }

    pub fn with_keys(
        mut self,
        active: Option<&str>,
        keys: std::collections::BTreeMap<String, VerificationKey>,
        legacy_until: Option<i64>,
    ) -> CoreResult<Self> {
        if keys.keys().any(|id| {
            id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }) || keys.values().any(|k| k.secret.len() < 32)
        {
            return Err(CoreError::invalid("invalid JWT verification key"));
        }
        if let Some(id) = active {
            let k = keys.get(id).ok_or_else(|| CoreError::invalid("active JWT key is missing"))?;
            if k.verify_until.is_some() {
                return Err(CoreError::invalid("active JWT key cannot have a retirement bound"));
            }
            self.enc = EncodingKey::from_secret(k.secret.as_bytes());
            self.key_id = Some(id.into());
        }
        self.retained = keys;
        self.legacy_until = legacy_until;
        Ok(self)
    }
    fn header(&self) -> CoreResult<Header> {
        if self.key_id.is_none() && self.legacy_until.is_some_and(|t| Utc::now().timestamp() >= t) {
            return Err(CoreError::Unauthorized("retired legacy key".into()));
        }
        let mut h = Header::new(Algorithm::HS256);
        h.kid = self.key_id.clone();
        Ok(h)
    }
    fn decoding_key(&self, token: &str) -> CoreResult<DecodingKey> {
        let h =
            jsonwebtoken::decode_header(token).map_err(|_| CoreError::Unauthorized("invalid legacy session".into()))?;
        if h.alg != Algorithm::HS256 || h.crit.as_ref().is_some_and(|v| !v.is_empty()) {
            return Err(CoreError::Unauthorized("invalid legacy session".into()));
        }
        if let Some(id) = h.kid {
            let k = self.retained.get(&id).ok_or_else(|| CoreError::Unauthorized("unknown legacy key".into()))?;
            if k.verify_until.is_some_and(|t| Utc::now().timestamp() >= t) {
                return Err(CoreError::Unauthorized("retired legacy key".into()));
            }
            Ok(DecodingKey::from_secret(k.secret.as_bytes()))
        } else {
            if self.legacy_until.is_some_and(|t| Utc::now().timestamp() >= t) {
                return Err(CoreError::Unauthorized("retired legacy key".into()));
            }
            Ok(self.dec.clone())
        }
    }
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// 签发 JWT。
    pub fn issue(&self, user_id: &str, tenant_id: &str, role: &str) -> CoreResult<String> {
        self.issue_with_generation(user_id, tenant_id, role, 0)
    }
    /// 兼容本地调用时显式绑定初始成员世代，认证仍核验双世代。
    pub fn issue_with_generation(
        &self,
        user_id: &str,
        tenant_id: &str,
        role: &str,
        generation: i64,
    ) -> CoreResult<String> {
        self.issue_workspace(user_id, tenant_id, role, generation, 0)
    }

    pub fn issue_workspace(
        &self,
        user_id: &str,
        tenant_id: &str,
        role: &str,
        generation: i64,
        membership_generation: i64,
    ) -> CoreResult<String> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            profile: "workspace".into(),
            membership_generation,
            generation,
            sub: user_id.into(),
            tid: tenant_id.into(),
            role: role.into(),
            iss: JWT_ISSUER.into(),
            iat: now,
            exp: now + self.ttl_secs as i64,
        };
        encode(&self.header()?, &claims, &self.enc).map_err(|e| CoreError::internal(format!("jwt encode failed: {e}")))
    }

    pub fn issue_account(&self, user_id: &str, generation: i64) -> CoreResult<String> {
        let now = Utc::now().timestamp();
        let claims = AccountClaims {
            profile: "account".into(),
            sub: user_id.into(),
            generation,
            iss: JWT_ISSUER.into(),
            iat: now,
            exp: now + self.ttl_secs as i64,
        };
        encode(&self.header()?, &claims, &self.enc).map_err(|e| CoreError::internal(format!("jwt encode failed: {e}")))
    }

    pub fn verify_account(&self, token: &str) -> CoreResult<AccountClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[JWT_ISSUER]);
        validation.leeway = 30;
        let claims = decode::<AccountClaims>(token, &self.decoding_key(token)?, &validation)
            .map_err(|_| CoreError::Unauthorized("invalid account session".into()))?
            .claims;
        if claims.profile != "account" || claims.generation < 0 {
            return Err(CoreError::Unauthorized("invalid account session profile".into()));
        }
        Ok(claims)
    }

    /// 校验并解码 JWT。
    pub fn verify(&self, token: &str) -> CoreResult<Claims> {
        let mut v = Validation::new(Algorithm::HS256);
        v.set_issuer(&[JWT_ISSUER]);
        v.leeway = 30;
        decode::<Claims>(token, &self.decoding_key(token)?, &v)
            .and_then(|d| {
                if d.claims.profile == "workspace" && d.claims.generation >= 0 && d.claims.membership_generation >= 0 {
                    Ok(d.claims)
                } else {
                    Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into())
                }
            })
            .map_err(|e| CoreError::Unauthorized(format!("invalid token: {e}")))
    }
}

/// 生成新的 API Token 明文（约 244 bit 随机熵）。
pub fn generate_api_token() -> String {
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    format!("{API_TOKEN_PREFIX}{}{}", hex::encode(a.as_bytes()), hex::encode(b.as_bytes()))
}

/// API Token 入库哈希。
pub fn hash_api_token(plaintext: &str) -> String {
    sha256_hex(plaintext.as_bytes())
}

/// 生成随机密钥（十六进制，64 字符），用于初始化 JWT secret。
pub fn generate_secret() -> String {
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    format!("{}{}", hex::encode(a.as_bytes()), hex::encode(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_roundtrip_and_tamper() {
        let codec = JwtCodec::new(&[7u8; 32], 3600).unwrap();
        let t = codec.issue("u1", "t1", "owner").unwrap();
        let c = codec.verify(&t).unwrap();
        assert_eq!((c.sub.as_str(), c.tid.as_str(), c.role.as_str()), ("u1", "t1", "owner"));
        let other = JwtCodec::new(&[8u8; 32], 3600).unwrap();
        assert!(other.verify(&t).is_err());
        assert!(JwtCodec::new(b"short", 10).is_err());
    }

    #[test]
    fn api_tokens_are_prefixed_and_unique() {
        let a = generate_api_token();
        assert!(a.starts_with(API_TOKEN_PREFIX));
        assert_eq!(a.len(), 4 + 64);
        assert_ne!(a, generate_api_token());
        assert_eq!(hash_api_token(&a), hash_api_token(&a));
    }
}

/// 账户会话使用互斥的载荷结构，工作区字段不能被忽略。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountClaims {
    pub profile: String,
    pub sub: String,
    pub generation: i64,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn account_workspace_and_legacy_profiles_are_exclusive() {
        let codec = JwtCodec::new(&[3; 32], 3600).unwrap();
        let account = codec.issue_account("user", 2).unwrap();
        let workspace = codec.issue_workspace("user", "tenant", "owner", 2, 7).unwrap();
        assert_eq!(codec.verify(&workspace).unwrap().membership_generation, 7);
        assert!(codec.verify(&account).is_err());
        assert!(codec.verify_account(&workspace).is_err());
        assert_eq!(codec.verify_account(&account).unwrap().generation, 2);
        #[derive(Serialize)]
        struct LegacyClaims<'a> {
            sub: &'a str,
            tid: &'a str,
            role: &'a str,
            iss: &'a str,
            exp: i64,
            generation: i64,
        }
        let legacy = encode(
            &Header::new(Algorithm::HS256),
            &LegacyClaims {
                sub: "user",
                tid: "tenant",
                role: "owner",
                iss: JWT_ISSUER,
                exp: Utc::now().timestamp() + 3600,
                generation: 2,
            },
            &codec.enc,
        )
        .unwrap();
        assert!(codec.verify(&legacy).is_err());
        assert!(codec.verify_account(&legacy).is_err());
    }
}

/// 轮换期间的保留密钥，所有普通 Debug 输出脱敏。
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationKey {
    pub secret: String,
    pub verify_until: Option<i64>,
}
impl std::fmt::Debug for VerificationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationKey")
            .field("secret", &"[REDACTED]")
            .field("verify_until", &self.verify_until)
            .finish()
    }
}

#[cfg(test)]
mod key_rotation_tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn legacy_key_overlap_kid_rejection_retirement_and_restart() {
        let legacy = JwtCodec::new(&[1; 32], 3600).unwrap();
        let old = legacy.issue_account("account", 0).unwrap();
        let keys = BTreeMap::from([("one".into(), VerificationKey { secret: "k".repeat(32), verify_until: None })]);
        let rotated = JwtCodec::new(&[1; 32], 3600).unwrap().with_keys(Some("one"), keys.clone(), None).unwrap();
        let token = rotated.issue_account("account", 0).unwrap();
        let restarted = JwtCodec::new(&[1; 32], 3600).unwrap().with_keys(Some("one"), keys, None).unwrap();
        assert!(restarted.verify_account(&token).is_ok());
        assert!(restarted.verify_account(&old).is_ok());
        assert!(legacy.verify_account(&token).is_err());
        let retired = JwtCodec::new(&[1; 32], 3600).unwrap().with_keys(None, Default::default(), Some(0)).unwrap();
        assert!(retired.verify_account(&old).is_err());
        assert!(retired.issue_account("account", 0).is_err());
    }
}
