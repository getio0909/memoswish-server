//! OAuth 与 OIDC 共用流程原语；保留既有摘要域以兼容持久凭据。

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use memoswish_core::{CoreError, CoreResult};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn secret(prefix: &str) -> CoreResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| CoreError::internal("OS random generator unavailable"))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(format!("learntok-oauth-v1\0{value}")))
}
pub fn equal(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
pub fn now() -> i64 {
    Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_digest_domain_and_rfc7636_pkce_vector_are_unchanged() {
        assert_eq!(digest("legacy-token"), "0e567627fa8e6036711af13d544e52bdd3bac8ddaba83db0538b9352ee02eb6f");
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(equal("same", "same"));
        assert!(!equal("same", "different"));
        let token = secret("test_").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(token.strip_prefix("test_").unwrap()).unwrap().len(), 32);
    }
}
