//! 普通 ID Token 使用维护中的 OIDC verifier；网络与 JWK 收敛策略由外层保留。
use super::*;
use openidconnect::{
    ClaimsVerificationError, ClientId, IssuerUrl, Nonce, SignatureVerificationError,
    core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm},
};

pub(super) fn verify(
    p: &OidcProvider,
    client: &str,
    token: &str,
    nonce: &str,
    key: &jsonwebtoken::jwk::Jwk,
    alg: Algorithm,
) -> Result<serde_json::Value, bool> {
    let keys: CoreJsonWebKeySet = serde_json::from_value(serde_json::json!({"keys":[key]})).map_err(|_| false)?;
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(client.into()),
        IssuerUrl::new(p.issuer.clone()).map_err(|_| false)?,
        keys,
    )
    .set_allowed_algs([match alg {
        Algorithm::RS256 => CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Algorithm::ES256 => CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        _ => return Err(false),
    }])
    .set_time_fn(|| Utc::now() - chrono::Duration::seconds(30))
    .set_issue_time_verifier_fn(|iat| {
        if iat.timestamp() > now() + 30 || iat.timestamp() < now() - 86400 {
            Err("invalid issue time".into())
        } else {
            Ok(())
        }
    })
    .set_other_audience_verifier_fn(|aud| {
        aud.as_str() == p.client_id || p.native_client_ids.iter().any(|n| n == aud.as_str())
    });
    let parsed: CoreIdToken = token.parse().map_err(|_| false)?;
    parsed.claims(&verifier, &Nonce::new(nonce.into())).map_err(|e| {
        matches!(e, ClaimsVerificationError::SignatureVerification(SignatureVerificationError::CryptoError(_)))
    })?;
    // 通过签名验证后保留未知扩展字段，供已有严格 azp/nbf/资料策略使用。
    let payload = token.split('.').nth(1).ok_or(false)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| false)?;
    serde_json::from_slice(&bytes).map_err(|_| false)
}
