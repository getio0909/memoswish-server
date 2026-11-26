//! 测试时生成 RSA-2048 / P-256 密钥，所有上游调用仅访问本地 mock。
use super::{app::AppState, config::Config};
use axum::{
    Json, Router,
    body::Body,
    extract::{Form, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use memoswish_auth::{
    oidc::{OidcService, apple_client_secret, challenge, now},
    oidc_config::*,
};
use memoswish_protocol::*;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;

#[path = "tests/compatibility_oidc.rs"]
mod compatibility;

struct Keys {
    rsa: EncodingKey,
    jwk: Value,
    ec: EncodingKey,
    ec_jwk: Value,
    ec_pem: String,
}
static KEYS: LazyLock<Keys> = LazyLock::new(|| keys("one"));
static ROTATED: LazyLock<Keys> = LazyLock::new(|| keys("two"));
fn keys(kid: &str) -> Keys {
    let rsa = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let jwk = json!({"kty":"RSA","alg":"RS256","use":"sig","kid":kid,"n":URL_SAFE_NO_PAD.encode(rsa.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_bytes_be())});
    let mut secret = [0; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    let ec = p256::SecretKey::from_slice(&secret).unwrap();
    let pk = ec.public_key();
    use p256::elliptic_curve::sec1::ToSec1Point;
    let point = pk.to_sec1_point(false);
    Keys {
        rsa: EncodingKey::from_rsa_der(rsa.to_pkcs1_der().unwrap().as_bytes()),
        jwk,
        ec: EncodingKey::from_ec_der(ec.to_pkcs8_der().unwrap().as_bytes()),
        ec_jwk: json!({"kty":"EC","crv":"P-256","alg":"ES256","kid":kid,"x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())}),
        ec_pem: ec.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
    }
}
fn signed(c: &Value, keys: &Keys, ec: bool) -> String {
    let mut h = Header::new(if ec { Algorithm::ES256 } else { Algorithm::RS256 });
    h.kid = Some(keys.jwk["kid"].as_str().unwrap().into());
    jsonwebtoken::encode(&h, c, if ec { &keys.ec } else { &keys.rsa }).unwrap()
}
fn claims(issuer: &str, nonce: &str, sub: &str) -> Value {
    json!({"iss":issuer,"aud":"browser-client","sub":sub,"exp":now()+600,"iat":now(),"nonce":nonce,"email":"ada@example.com","email_verified":true,"name":"Ada"})
}
struct Mock {
    base: String,
    issuer: String,
    kind: String,
    jwks: Mutex<Value>,
    codes: Mutex<HashMap<String, Value>>,
    pkce: Mutex<HashMap<String, String>>,
    fetches: AtomicUsize,
    tokens: AtomicUsize,
    revocations: AtomicUsize,
    mode: Mutex<String>,
    ttl: AtomicUsize,
}
async fn discovery(State(m): State<Arc<Mock>>) -> Json<Value> {
    let hostile = *m.mode.lock().unwrap() == "hostile";
    Json(
        json!({"issuer":m.issuer,"authorization_endpoint":format!("{}/authorize",m.base),"token_endpoint":format!("{}/token",m.base),"jwks_uri":if hostile{"http://unconfigured.invalid/jwks".to_string()}else{format!("{}/jwks",m.base)},"revocation_endpoint":format!("{}/revoke",m.base),"code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["RS256","ES256"]}),
    )
}
async fn jwks(State(m): State<Arc<Mock>>) -> Response {
    m.fetches.fetch_add(1, Ordering::SeqCst);
    let mode = m.mode.lock().unwrap().clone();
    if mode == "slow" {
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }
    if mode == "oversized" {
        return "x".repeat(256 * 1024 + 1).into_response();
    }
    if mode == "redirect" {
        return (StatusCode::FOUND, [(header::LOCATION, format!("{}/trap", m.base))]).into_response();
    }
    let mut r = Json(m.jwks.lock().unwrap().clone()).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, format!("max-age={}", m.ttl.load(Ordering::SeqCst)).parse().unwrap());
    r
}
async fn token(State(m): State<Arc<Mock>>, Form(p): Form<HashMap<String, String>>) -> Response {
    m.tokens.fetch_add(1, Ordering::SeqCst);
    if m.kind == "apple" {
        let mut v = jsonwebtoken::Validation::new(Algorithm::ES256);
        v.set_audience(&["https://appleid.apple.com"]);
        v.set_issuer(&["team"]);
        let key = jsonwebtoken::DecodingKey::from_jwk(&serde_json::from_value(KEYS.ec_jwk.clone()).unwrap()).unwrap();
        let data = jsonwebtoken::decode::<Value>(&p["client_secret"], &key, &v).unwrap();
        assert_eq!(data.claims["sub"], p["client_id"]);
        assert_eq!(data.claims["exp"].as_i64().unwrap() - data.claims["iat"].as_i64().unwrap(), 300);
    }
    if let Some(expected) = m.pkce.lock().unwrap().remove(&p["code"]) {
        assert_eq!(challenge(&p["code_verifier"]), expected);
    }
    match m.codes.lock().unwrap().remove(&p["code"]) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))).into_response(),
    }
}
async fn revoke(State(m): State<Arc<Mock>>, Form(p): Form<HashMap<String, String>>) -> Response {
    assert_eq!(p["token"], "apple-refresh-secret");
    assert_eq!(p["token_type_hint"], "refresh_token");
    m.revocations.fetch_add(1, Ordering::SeqCst);
    if *m.mode.lock().unwrap() == "revoke-fail" {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    } else {
        StatusCode::OK.into_response()
    }
}
struct Fixture {
    st: AppState,
    app: Router,
    m: Arc<Mock>,
    task: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn cleanup(mut self) {
        crate::runtime::cleanup_test_app(&self.dir, &[&self.st]).await;
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
async fn fixture(kind: &str) -> Fixture {
    fixture_with_alias(kind, false).await
}
async fn fixture_with_alias(kind: &str, alias: bool) -> Fixture {
    fixture_with_database(kind, alias, None).await
}
async fn fixture_with_database(kind: &str, alias: bool, database_url: Option<String>) -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let issuer = match kind {
        "google" => "https://accounts.google.com".into(),
        "apple" => "https://appleid.apple.com".into(),
        _ => base.clone(),
    };
    let m = Arc::new(Mock {
        base: base.clone(),
        issuer: issuer.clone(),
        kind: kind.into(),
        jwks: Mutex::new(json!({"keys":[KEYS.jwk.clone(),KEYS.ec_jwk.clone()]})),
        codes: Mutex::new(HashMap::new()),
        pkce: Mutex::new(HashMap::new()),
        fetches: AtomicUsize::new(0),
        tokens: AtomicUsize::new(0),
        revocations: AtomicUsize::new(0),
        mode: Mutex::new(String::new()),
        ttl: AtomicUsize::new(3600),
    });
    // 相同 kid 的两把不同算法公钥是歧义键，测试默认只公开 RSA。
    *m.jwks.lock().unwrap() = json!({"keys":[KEYS.jwk.clone()]});
    let routes = Router::new()
        .route("/discovery", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .route(
            "/trap",
            get(|| async {
                panic!("redirect was followed");
                #[allow(unreachable_code)]
                StatusCode::OK
            }),
        )
        .with_state(m.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, routes).await.unwrap();
    });
    let dir = std::env::temp_dir().join(format!("memoswish-oidc-{}", memoswish_core::ids::new_id()));
    let mut config = Config {
        data_dir: dir.clone(),
        database_url,
        mode: DeploymentMode::MultiTenant,
        registration_open: true,
        seed_demo: false,
        oidc: OidcConfig {
            enabled: true,
            public_base_url: "https://learn.example".into(),
            encryption_key: URL_SAFE_NO_PAD.encode([42u8; 32]),
            encryption_key_id: Default::default(),
            encryption_keys: Default::default(),
            legacy_encryption_until: None,
            return_uris: vec!["com.memoswish.app:/auth/callback".into()],
            providers: vec![OidcProvider {
                id: "test".into(),
                kind: kind.into(),
                name: "Test".into(),
                issuer,
                discovery_url: format!("{base}/discovery"),
                client_id: "browser-client".into(),
                native_client_ids: vec!["native-client".into()],
                allowed_hosts: vec!["127.0.0.1".into(), "accounts.google.com".into(), "appleid.apple.com".into()],
                allow_private_network: true,
                algorithms: if kind == "apple" { vec!["RS256".into()] } else { vec!["RS256".into(), "ES256".into()] },
                apple_team_id: "team".into(),
                apple_key_id: "signing-key".into(),
                apple_private_key: KEYS.ec_pem.clone(),
                ..Default::default()
            }],
        },
        ..Default::default()
    };
    if alias {
        let provider = OidcProvider { id: "alias".into(), ..config.oidc.providers[0].clone() };
        config.oidc.providers.push(provider);
    }
    let st = AppState::build(config).await.unwrap();
    let app = super::api::router(st.clone());
    Fixture { st, app, m, task, dir }
}
async fn send(
    app: &Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut r = Request::builder().method(method).uri(path);
    if let Some(b) = bearer {
        r = r.header(header::AUTHORIZATION, format!("Bearer {b}"));
    }
    if let Some(c) = cookie {
        r = r.header(header::COOKIE, c);
    }
    let req = if let Some(body) = body {
        r.header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())).unwrap()
    } else {
        r.body(Body::empty()).unwrap()
    };
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}
const VERIFIER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn start_request(native: bool) -> Value {
    json!({"return_uri":"com.memoswish.app:/auth/callback","app_state":"app-state","code_challenge":challenge(VERIFIER),"native_client_id":if native{Some("native-client")}else{None}})
}
struct Browser {
    provider: String,
    upstream: url::Url,
    cookie: String,
    link_jwt: Option<String>,
}
async fn begin(f: &Fixture, link: Option<&str>) -> Browser {
    begin_provider(f, "test", link).await
}
async fn begin_provider(f: &Fixture, provider: &str, link: Option<&str>) -> Browser {
    let suffix = if link.is_some() { "link/start" } else { "start" };
    let path = format!("/v1/auth/oidc/{provider}/{suffix}");
    let (s, h, a) = send(&f.app, "POST", &path, link, None, Some(start_request(false))).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert_eq!(h["cache-control"], "no-store");
    let launch = url::Url::parse(a["launch_url"].as_str().unwrap()).unwrap();
    let path = format!("{}?{}", launch.path(), launch.query().unwrap());
    let (s, h, _) = send(&f.app, "GET", &path, None, None, None).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let cookie = h[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
    assert!(h[header::SET_COOKIE].to_str().unwrap().contains("Secure; HttpOnly; SameSite=None"));
    Browser {
        provider: provider.into(),
        upstream: url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap(),
        cookie,
        link_jwt: link.map(str::to_string),
    }
}
fn query(b: &Browser, key: &str) -> String {
    b.upstream.query_pairs().find(|(k, _)| k == key).unwrap().1.to_string()
}
fn upstream(f: &Fixture, b: &Browser, sub: &str, extra: Value) -> String {
    let code = memoswish_core::ids::new_id();
    let mut c = claims(&f.m.issuer, &query(b, "nonce"), sub);
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    let token = signed(&c, &KEYS, false);
    f.m.codes.lock().unwrap().insert(code.clone(), json!({"id_token":token,"refresh_token":"apple-refresh-secret"}));
    if f.m.kind != "apple" {
        f.m.pkce.lock().unwrap().insert(code.clone(), query(b, "code_challenge"));
    }
    code
}
async fn callback(
    f: &Fixture,
    b: &Browser,
    code: &str,
    apple_user: Option<&str>,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let params = [("state", query(b, "state")), ("code", code.to_string())];
    let mut data = url::form_urlencoded::Serializer::new(String::new());
    data.extend_pairs(params);
    if let Some(user) = apple_user {
        data.append_pair("user", user);
    }
    let encoded = data.finish();
    if f.m.kind == "apple" {
        let mut r = Request::post(format!("/v1/auth/oidc/{}/callback", b.provider))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            r = r.header(header::COOKIE, cookie);
        }
        let response = f.app.clone().oneshot(r.body(Body::from(encoded)).unwrap()).await.unwrap();
        let s = response.status();
        let h = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (s, h, serde_json::from_slice(&body).unwrap_or(Value::Null))
    } else {
        send(&f.app, "GET", &format!("/v1/auth/oidc/{}/callback?{encoded}", b.provider), None, cookie, None).await
    }
}
async fn finish_browser(f: &Fixture, b: &Browser, sub: &str, extra: Value, user: Option<&str>) -> Value {
    let code = upstream(f, b, sub, extra);
    let (s, h, body) = callback(f, b, &code, user, Some(&b.cookie)).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{body}");
    let target = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(target.scheme(), "com.memoswish.app");
    assert!(!target.has_host());
    assert_eq!(target.path(), "/auth/callback");
    assert!(!target.as_str().contains("id_token"));
    assert!(!target.as_str().contains("access_token"));
    let params: HashMap<_, _> = target.query_pairs().into_owned().collect();
    assert_eq!(params["state"], "app-state");
    let (s, _, auth) = send(
        &f.app,
        "POST",
        &format!("/v1/auth/oidc/{}/complete", b.provider),
        b.link_jwt.as_deref(),
        None,
        Some(json!({"code":params["code"],"code_verifier":VERIFIER})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{auth}");
    let (s, _, _) = send(
        &f.app,
        "POST",
        &format!("/v1/auth/oidc/{}/complete", b.provider),
        b.link_jwt.as_deref(),
        None,
        Some(json!({"code":params["code"],"code_verifier":VERIFIER})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    auth
}

#[tokio::test]
async fn oidc_browser_state_cookie_pkce_handoff_replay_and_existing_login() {
    browser_replay_case(fixture("generic").await).await;
}
async fn browser_replay_case(mut f: Fixture) {
    let b = begin(&f, None).await;
    assert_eq!(query(&b, "code_challenge_method"), "S256");
    let code = upstream(&f, &b, "subject", json!({}));
    assert_eq!(callback(&f, &b, &code, None, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(callback(&f, &b, &code, None, Some("__Host-lti-other=wrong")).await.0, StatusCode::UNAUTHORIZED);
    let auth = finish_browser(&f, &b, "subject", json!({}), None).await;
    assert_eq!(callback(&f, &b, &code, None, Some(&b.cookie)).await.0, StatusCode::UNAUTHORIZED);
    let b = begin(&f, None).await;
    crate::runtime::drain_test_state(&f.st).await;
    f.st = AppState::build(f.st.config.as_ref().clone()).await.unwrap();
    f.app = super::api::router(f.st.clone());
    let again = finish_browser(&f, &b, "subject", json!({"name":"Changed"}), None).await;
    assert_eq!(again["user"], auth["user"]);
    assert_eq!(f.m.fetches.load(Ordering::SeqCst), 2);
    assert_eq!(send(&f.app, "GET", "/v1/me", auth["access_token"].as_str(), None, None).await.0, StatusCode::OK);
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_google_native_nonce_audience_and_one_use() {
    let f = fixture("google").await;
    let (s, _, a) = send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(start_request(true))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(a.get("launch_url").is_none());
    let mut c = claims(&f.m.issuer, a["nonce"].as_str().unwrap(), "native-sub");
    c["aud"] = json!("native-client");
    let req = json!({"attempt_id":a["attempt_id"],"id_token":signed(&c,&KEYS,false),"nonce":a["nonce"],"code_verifier":VERIFIER});
    let mut bad = req.clone();
    bad["nonce"] = json!("bad");
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/test/exchange", None, None, Some(bad)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, _, auth) = send(&f.app, "POST", "/v1/auth/oidc/test/exchange", None, None, Some(req.clone())).await;
    assert_eq!(s, StatusCode::OK, "{auth}");
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/test/exchange", None, None, Some(req)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&f.app, "GET", "/v1/me", Some(&signed(&c, &KEYS, false)), None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_id_token_validation_rejects_all_required_claim_failures() {
    let f = fixture("generic").await;
    let svc = f.st.oidc.as_ref().unwrap();
    let good = claims(&f.m.issuer, "nonce", "sub");
    svc.validate_id_token("test", &signed(&good, &KEYS, false), "nonce", "browser-client").await.unwrap();
    let mutations = vec![
        ("iss", json!("https://attacker.example")),
        ("iss", json!([f.m.issuer, "https://attacker.example"])),
        ("iss", json!([f.m.issuer])),
        ("aud", json!("wrong")),
        ("aud", json!(["browser-client", "evil"])),
        ("iat", json!(now() + 60)),
        ("iat", Value::Null),
        ("iat", json!(now() - 86460)),
        ("exp", json!(now() - 60)),
        ("exp", json!(now() - 1)),
        ("nonce", json!("wrong")),
        ("nonce", Value::Null),
        ("sub", json!("")),
        ("azp", json!("other")),
        ("aud", json!(["browser-client", "native-client"])),
    ];
    for (key, value) in mutations {
        let mut c = good.clone();
        c[key] = value;
        assert!(
            svc.validate_id_token("test", &signed(&c, &KEYS, false), "nonce", "browser-client").await.is_err(),
            "accepted invalid {key}"
        );
    }
    let mut valid = good.clone();
    valid["aud"] = json!(["browser-client", "native-client"]);
    valid["azp"] = json!("browser-client");
    svc.validate_id_token("test", &signed(&valid, &KEYS, false), "nonce", "browser-client").await.unwrap();
    let mut h = Header::new(Algorithm::HS256);
    h.kid = Some("one".into());
    let confused = jsonwebtoken::encode(&h, &good, &EncodingKey::from_secret(b"public key")).unwrap();
    assert!(svc.validate_id_token("test", &confused, "nonce", "browser-client").await.is_err());
    assert!(svc.validate_id_token("test", "a.b.c.d.e", "nonce", "browser-client").await.is_err());
    assert!(svc.validate_id_token("test", &signed(&good, &KEYS, false), "nonce", "unconfigured-native").await.is_err());
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_jwks_cache_rotation_coalescing_and_algorithm_key_policy() {
    let f = fixture("generic").await;
    let svc = f.st.oidc.as_ref().unwrap();
    let c = claims(&f.m.issuer, "nonce", "sub");
    svc.validate_id_token("test", &signed(&c, &KEYS, false), "nonce", "browser-client").await.unwrap();
    *f.m.jwks.lock().unwrap() = json!({"keys":[ROTATED.jwk.clone()]});
    let rotated = signed(&c, &ROTATED, false);
    let (a, b) = tokio::join!(
        svc.validate_id_token("test", &rotated, "nonce", "browser-client"),
        svc.validate_id_token("test", &rotated, "nonce", "browser-client")
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(f.m.fetches.load(Ordering::SeqCst), 2);
    for _ in 0..5 {
        assert!(svc.validate_id_token("test", &signed(&c, &KEYS, false), "nonce", "browser-client").await.is_err());
    }
    assert_eq!(f.m.fetches.load(Ordering::SeqCst), 2, "unknown-key refresh must be throttled");
    let f = fixture("generic").await;
    *f.m.jwks.lock().unwrap() = json!({"keys":[KEYS.ec_jwk.clone()]});
    f.st.oidc
        .as_ref()
        .unwrap()
        .validate_id_token(
            "test",
            &signed(&claims(&f.m.issuer, "nonce", "sub"), &KEYS, true),
            "nonce",
            "browser-client",
        )
        .await
        .unwrap();
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_jwks_ambiguous_wrong_use_and_hostile_discovery_rejected() {
    for mode in ["duplicate", "wrong-use", "many", "hostile", "redirect", "oversized"] {
        let f = fixture("generic").await;
        match mode {
            "duplicate" => *f.m.jwks.lock().unwrap() = json!({"keys":[KEYS.jwk.clone(),KEYS.jwk.clone()]}),
            "wrong-use" => {
                let mut k = KEYS.jwk.clone();
                k["use"] = json!("enc");
                *f.m.jwks.lock().unwrap() = json!({"keys":[k]});
            }
            "many" => *f.m.jwks.lock().unwrap() = json!({"keys":vec![KEYS.jwk.clone();33]}),
            _ => *f.m.mode.lock().unwrap() = mode.into(),
        };
        assert!(
            f.st.oidc
                .as_ref()
                .unwrap()
                .validate_id_token("test", &signed(&claims(&f.m.issuer, "n", "s"), &KEYS, false), "n", "browser-client")
                .await
                .is_err(),
            "accepted {mode}"
        );
        f.cleanup().await;
    }
}

#[tokio::test]
async fn oidc_jwks_timeout_expiry_and_private_network_policy() {
    let f = fixture("generic").await;
    *f.m.mode.lock().unwrap() = "slow".into();
    let start = std::time::Instant::now();
    assert!(
        f.st.oidc
            .as_ref()
            .unwrap()
            .validate_id_token("test", &signed(&claims(&f.m.issuer, "n", "s"), &KEYS, false), "n", "browser-client")
            .await
            .is_err()
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(6));
    let f = fixture("generic").await;
    f.m.ttl.store(0, Ordering::SeqCst);
    let svc = f.st.oidc.as_ref().unwrap();
    let token = signed(&claims(&f.m.issuer, "n", "s"), &KEYS, false);
    svc.validate_id_token("test", &token, "n", "browser-client").await.unwrap();
    svc.validate_id_token("test", &token, "n", "browser-client").await.unwrap();
    assert_eq!(f.m.fetches.load(Ordering::SeqCst), 2);
    let mut cfg = f.st.config.oidc.clone();
    let p = &mut cfg.providers[0];
    p.issuer = "https://localhost".into();
    p.discovery_url = "https://localhost/discovery".into();
    p.allowed_hosts = vec!["localhost".into()];
    p.allow_private_network = false;
    let svc = OidcService::new(cfg, f.st.repo.clone(), f.st.services.auth.clone(), "free".into()).unwrap();
    assert!(svc.validate_id_token("test", &token, "n", "browser-client").await.is_err());
    assert_eq!(f.m.fetches.load(Ordering::SeqCst), 2);
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_apple_form_post_first_name_relay_client_secret_and_revocation() {
    let f = fixture("apple").await;
    let b = begin(&f, None).await;
    assert_eq!(query(&b, "response_mode"), "form_post");
    assert!(!b.upstream.query_pairs().any(|(k, _)| k == "code_challenge"));
    let auth = finish_browser(
        &f,
        &b,
        "apple-sub",
        json!({"name":null,"email":"relay@private.icloud.com","email_verified":"true"}),
        Some(r#"{"name":{"firstName":"  Ada\n","lastName":"Lovelace"}}"#),
    )
    .await;
    assert_eq!(auth["user"]["display_name"], "Ada Lovelace");
    let b = begin(&f, None).await;
    let again = finish_browser(&f, &b, "apple-sub", json!({"name":null,"email":null}), None).await;
    assert_eq!(auth["user"], again["user"]);
    let jwt = auth["access_token"].as_str().unwrap();
    let (s, _, export) = send(&f.app, "GET", "/v1/account/export", Some(jwt), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(export["federated_identities"][0]["email"], "relay@private.icloud.com");
    assert_eq!(export["federated_identities"][0]["email_verified"], true);
    let text = export.to_string();
    for secret in ["apple-refresh-secret", "credential", "password_hash", "token_hash", "verifier_ciphertext"] {
        assert!(!text.contains(secret), "leaked {secret}");
    }
    let profile = auth["user"].clone();
    let key = format!("tenants/{}/imports/a.png", profile["tenant_id"].as_str().unwrap());
    f.st.store.put(&key, b"private image".to_vec(), "image/png").await.unwrap();
    *f.m.mode.lock().unwrap() = "revoke-fail".into();
    assert_eq!(send(&f.app, "DELETE", "/v1/account", Some(jwt), None, None).await.0, StatusCode::ACCEPTED);
    assert!(
        f.st.repo
            .get_user(profile["tenant_id"].as_str().unwrap(), profile["user_id"].as_str().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(!f.dir.join("assets").join(&key).exists());
    let pending = f.st.repo.account_erasure_jobs().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(f.st.repo.account_erased_tenant(profile["tenant_id"].as_str().unwrap()).await.unwrap());
    assert_eq!(f.st.repo.erasure_work(&pending[0].id).await.unwrap().unwrap().progress, "blocked");
    assert_eq!(
        pending
            .iter()
            .filter(|j| j.purge_assets
                && j.tenant_id.as_deref() == profile["tenant_id"].as_str()
                && j.credentials.is_empty())
            .count(),
        0
    );
    assert_eq!(
        pending.iter().filter(|j| j.tenant_id.is_none() && !j.purge_assets && j.credentials.len() == 1).count(),
        1
    );
    assert_eq!(send(&f.app, "GET", "/v1/me", Some(jwt), None, None).await.0, StatusCode::UNAUTHORIZED);
    *f.m.mode.lock().unwrap() = String::new();
    for job in f.st.repo.account_erasure_jobs().await.unwrap() {
        crate::account_tests::erasure_retry_due_for_test(&f.st, &job).await;
        super::account::finish(&f.st, &job).await.unwrap();
    }
    assert!(f.st.repo.account_erasure_jobs().await.unwrap().is_empty());
    assert_eq!(f.m.revocations.load(Ordering::SeqCst), 2);
    assert!(f.st.store.put(&key, b"late".to_vec(), "image/png").await.is_err());
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_apple_native_exchange_requires_code_and_gets_revocation_credential() {
    let f = fixture("apple").await;
    let (_, _, a) = send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(start_request(true))).await;
    let mut c = claims(&f.m.issuer, a["nonce"].as_str().unwrap(), "apple-native");
    c["aud"] = json!("native-client");
    let token = signed(&c, &KEYS, false);
    f.m.codes
        .lock()
        .unwrap()
        .insert("native-code".into(), json!({"id_token":token,"refresh_token":"apple-refresh-secret"}));
    let r = json!({"attempt_id":a["attempt_id"],"id_token":token,"nonce":a["nonce"],"code_verifier":VERIFIER,"authorization_code":"native-code"});
    let (s, _, auth) = send(&f.app, "POST", "/v1/auth/oidc/test/exchange", None, None, Some(r)).await;
    assert_eq!(s, StatusCode::OK, "{auth}");
    crate::account_tests::assert_erasure_response(
        &f.st,
        send(&f.app, "DELETE", "/v1/account", auth["access_token"].as_str(), None, None).await.0,
    )
    .await;
    assert_eq!(f.m.revocations.load(Ordering::SeqCst), 1);
    assert!(f.st.repo.account_erasure_jobs().await.unwrap().is_empty());
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_email_preaccount_takeover_requires_recent_explicit_linking() {
    let f = fixture("generic").await;
    let existing =
        f.st.services
            .auth
            .register(&RegisterRequest {
                email: "ada@example.com".into(),
                password: "password123".into(),
                display_name: "Existing".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let b = begin(&f, None).await;
    let code = upstream(&f, &b, "verified", json!({}));
    assert_eq!(callback(&f, &b, &code, None, Some(&b.cookie)).await.0, StatusCode::CONFLICT);
    let b = begin(&f, None).await;
    let separate = finish_browser(&f, &b, "unverified", json!({"email_verified":false}), None).await;
    assert_ne!(separate["user"]["user_id"], existing.user.user_id);
    let p = f.st.services.auth.authenticate(Some(&existing.access_token)).await.unwrap();
    let api = f.st.services.auth.create_api_token(&p, "agent", vec!["*".into()], None).await.unwrap();
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/test/link/start", Some(&api.plaintext), None, Some(start_request(false)))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let b = begin(&f, Some(&existing.access_token)).await;
    let linked = finish_browser(&f, &b, "verified", json!({}), None).await;
    assert_eq!(linked["user"]["user_id"], existing.user.user_id);
    let b = begin(&f, Some(separate["access_token"].as_str().unwrap())).await;
    let code = upstream(&f, &b, "verified", json!({}));
    let (_, h, _) = callback(&f, &b, &code, None, Some(&b.cookie)).await;
    let target = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    let code = target.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
    assert_eq!(
        send(
            &f.app,
            "POST",
            "/v1/auth/oidc/test/complete",
            b.link_jwt.as_deref(),
            None,
            Some(json!({"code":code,"code_verifier":VERIFIER}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let db = memoswish_storage::sqlite::SqliteRepository::connect(&f.st.config.database_url()).await.unwrap();
    sqlx::query("UPDATE recent_authentication SET expires_at=0").execute(db.pool()).await.unwrap();
    let refreshed = f.st.services.auth.refresh(&p).await.unwrap();
    assert_eq!(
        send(
            &f.app,
            "POST",
            "/v1/auth/oidc/test/link/start",
            Some(&refreshed.access_token),
            None,
            Some(start_request(false))
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "refresh cannot create interactive authentication"
    );
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_concurrent_provisioning_is_unique_and_closed_registration_keeps_linked_users() {
    let f = fixture("google").await;
    let svc = f.st.oidc.as_ref().unwrap();
    let request: OidcStartRequest = serde_json::from_value(start_request(true)).unwrap();
    let mut attempts = Vec::new();
    for _ in 0..8 {
        let a = svc.start("test", &request, None).await.unwrap();
        let mut c = claims(&f.m.issuer, a.nonce.as_ref().unwrap(), "same-subject");
        c["aud"] = json!("native-client");
        attempts.push(OidcExchangeRequest {
            attempt_id: a.attempt_id,
            id_token: signed(&c, &KEYS, false),
            nonce: a.nonce.unwrap(),
            code_verifier: VERIFIER.into(),
            authorization_code: None,
            apple_user: None,
        });
    }
    let mut set = tokio::task::JoinSet::new();
    for r in attempts {
        let svc = svc.clone();
        set.spawn(async move { svc.exchange("test", &r).await.unwrap() });
    }
    let mut users = std::collections::HashSet::new();
    while let Some(auth) = set.join_next().await {
        users.insert(auth.unwrap().user.user_id);
    }
    assert_eq!(users.len(), 1);
    let auth = memoswish_auth::AuthService::new(
        f.st.repo.clone(),
        memoswish_auth::AuthConfig {
            mode: DeploymentMode::MultiTenant,
            jwt_secret: "s".repeat(32),
            jwt_ttl_secs: 3600,
            registration_open: false,
            default_plan: "free".into(),
        },
    )
    .unwrap();
    let closed = OidcService::new(f.st.config.oidc.clone(), f.st.repo.clone(), auth, "free".into()).unwrap();
    for (sub, success) in [("same-subject", true), ("new-subject", false)] {
        let a = closed.start("test", &request, None).await.unwrap();
        let mut c = claims(&f.m.issuer, a.nonce.as_ref().unwrap(), sub);
        c["aud"] = json!("native-client");
        let result = closed
            .exchange(
                "test",
                &OidcExchangeRequest {
                    attempt_id: a.attempt_id,
                    id_token: signed(&c, &KEYS, false),
                    nonce: a.nonce.unwrap(),
                    code_verifier: VERIFIER.into(),
                    authorization_code: None,
                    apple_user: None,
                },
            )
            .await;
        assert_eq!(result.is_ok(), success);
    }
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_wrong_provider_duplicate_parameters_and_invalid_return_uri_fail_closed() {
    let f = fixture("generic").await;
    let mut bad = start_request(false);
    bad["return_uri"] = json!("https://evil.example");
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(bad)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/other/start", None, None, Some(start_request(false))).await.0,
        StatusCode::NOT_FOUND
    );
    let b = begin(&f, None).await;
    assert_eq!(
        send(&f.app, "GET", "/v1/auth/oidc/test/callback?state=a&state=b&code=x", None, Some(&b.cookie), None).await.0,
        StatusCode::BAD_REQUEST
    );
    let code = upstream(&f, &b, "sub", json!({}));
    let wrong = format!("/v1/auth/oidc/other/callback?state={}&code={code}", query(&b, "state"));
    assert_eq!(send(&f.app, "GET", &wrong, None, Some(&b.cookie), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(f.m.tokens.load(Ordering::SeqCst), 0);
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_config_redacts_keys_and_rejects_unsafe_profiles() {
    let f = fixture("apple").await;
    let mut cfg = f.st.config.as_ref().clone();
    cfg.oidc.providers[0].client_secret = "sensitive".into();
    let printed = toml::to_string(&cfg.redacted()).unwrap();
    assert!(!printed.contains("sensitive"));
    assert!(!printed.contains("BEGIN PRIVATE KEY"));
    assert!(!printed.contains(&cfg.oidc.encryption_key));
    let token = apple_client_secret(&cfg.oidc.providers[0], now()).unwrap();
    let header = jsonwebtoken::decode_header(&token).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some("signing-key"));
    cfg.oidc.providers[0].issuer = "https://evil.example".into();
    assert!(cfg.oidc.validate().is_err());
    cfg.oidc.providers[0].issuer = "https://appleid.apple.com".into();
    cfg.oidc.providers[0].algorithms = vec!["HS256".into()];
    assert!(cfg.oidc.validate().is_err());
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_apple_signed_events_revoke_sessions_and_require_fresh_consent() {
    let f = fixture("apple").await;
    let b = begin(&f, None).await;
    let auth = finish_browser(&f, &b, "event-sub", json!({}), None).await;
    let jwt = auth["access_token"].as_str().unwrap();
    let p = f.st.services.auth.authenticate(Some(jwt)).await.unwrap();
    let api = f.st.services.auth.create_api_token(&p, "agent", vec!["*".into()], None).await.unwrap();
    let at = now();
    let event = |kind: &str, id: &str, at: i64| json!({"iss":"https://appleid.apple.com","aud":"browser-client","iat":now(),"jti":id,"events":{"type":kind,"sub":"event-sub","event_time":at}});
    let notify = |c: Value| json!({"payload":signed(&c,&KEYS,false)});
    let mut invalid = event("consent-revoked", "bad", at);
    invalid["aud"] = json!("evil-client");
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/test/events", None, None, Some(notify(invalid))).await.0,
        StatusCode::UNAUTHORIZED
    );
    for issuer in
        [json!(["https://appleid.apple.com"]), json!(["https://appleid.apple.com", "https://attacker.example"])]
    {
        let mut array_issuer = event("consent-revoked", "array-issuer", at);
        array_issuer["iss"] = issuer;
        assert_eq!(
            send(&f.app, "POST", "/v1/auth/oidc/test/events", None, None, Some(notify(array_issuer))).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(f.st.services.auth.authenticate(Some(jwt)).await.is_ok());
    let revoked = notify(event("consent-revoked", "revoke-1", at));
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/test/events", None, None, Some(revoked.clone())).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/oidc/test/events", None, None, Some(revoked)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(f.st.repo.identity_generation(&p.tenant_id, &p.user_id).await.unwrap(), 1);
    assert!(f.st.services.auth.authenticate(Some(jwt)).await.is_err());
    assert!(f.st.services.auth.authenticate(Some(&api.plaintext)).await.is_err());
    let b = begin(&f, None).await;
    let code = upstream(&f, &b, "event-sub", json!({"iat":at}));
    assert_eq!(callback(&f, &b, &code, None, Some(&b.cookie)).await.0, StatusCode::UNAUTHORIZED);
    let b = begin(&f, None).await;
    let fresh = finish_browser(&f, &b, "event-sub", json!({"iat":at+1}), None).await;
    assert_eq!(fresh["user"], auth["user"]);
    let fresh_jwt = fresh["access_token"].as_str().unwrap();
    assert!(f.st.services.auth.authenticate(Some(fresh_jwt)).await.is_ok());
    for (kind, id, time) in [("email-disabled", "email-2", at + 2), ("email-enabled", "email-1", at - 1)] {
        assert_eq!(
            send(&f.app, "POST", "/v1/auth/oidc/test/events", None, None, Some(notify(event(kind, id, time)))).await.0,
            StatusCode::NO_CONTENT
        );
    }
    let export = f.st.repo.account_export(&p.tenant_id, &p.user_id, true).await.unwrap();
    assert_eq!(export["identity_status"][0]["email_forwarding"], "disabled");
    assert_eq!(
        send(
            &f.app,
            "POST",
            "/v1/auth/oidc/test/events",
            None,
            None,
            Some(notify(event("account-deleted", "delete", at + 3)))
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(f.st.services.auth.authenticate(Some(fresh_jwt)).await.is_err());
    let b = begin(&f, None).await;
    let code = upstream(&f, &b, "event-sub", json!({"iat":at+4}));
    assert_eq!(callback(&f, &b, &code, None, Some(&b.cookie)).await.0, StatusCode::UNAUTHORIZED);
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_same_kid_rotation_and_google_browser_are_supported() {
    let f = fixture("google").await;
    let svc = f.st.oidc.as_ref().unwrap();
    let token = claims(&f.m.issuer, "n", "s");
    svc.validate_id_token("test", &signed(&token, &KEYS, false), "n", "browser-client").await.unwrap();
    let mut rotated = ROTATED.jwk.clone();
    rotated["kid"] = json!("one");
    *f.m.jwks.lock().unwrap() = json!({"keys":[rotated]});
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some("one".into());
    let jwt = jsonwebtoken::encode(&h, &token, &ROTATED.rsa).unwrap();
    svc.validate_id_token("test", &jwt, "n", "browser-client").await.unwrap();
    assert_eq!(f.m.fetches.load(Ordering::SeqCst), 2);
    let f = fixture("google").await;
    let b = begin(&f, None).await;
    finish_browser(&f, &b, "google-browser", json!({}), None).await;
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_link_callback_is_pending_until_pkce_and_original_account_session() {
    let f = fixture("generic").await;
    let register = |email: &str| RegisterRequest {
        email: email.into(),
        password: "password123".into(),
        display_name: "Account".into(),
        tenant_name: None,
    };
    let attacker = f.st.services.auth.register(&register("attacker@example.com")).await.unwrap();
    let victim = f.st.services.auth.register(&register("victim@example.com")).await.unwrap();
    for (bearer, verifier) in [
        (None, VERIFIER),
        (Some(victim.access_token.as_str()), VERIFIER),
        (Some(attacker.access_token.as_str()), "wrong-verifier-that-has-the-required-length-000000"),
    ] {
        // 发起者提供 launch URL，另一浏览器接收 Cookie 和上游身份。
        let b = begin(&f, Some(&attacker.access_token)).await;
        let code = upstream(&f, &b, "victim-provider", json!({"email":null}));
        let (status, h, _) = callback(&f, &b, &code, None, Some(&b.cookie)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let export = f.st.repo.account_export(&attacker.user.tenant_id, &attacker.user.user_id, true).await.unwrap();
        assert!(export["federated_identities"].as_array().unwrap().is_empty());
        let target = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
        let code = target.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
        assert_eq!(
            send(
                &f.app,
                "POST",
                "/v1/auth/oidc/test/complete",
                bearer,
                None,
                Some(json!({"code":code,"code_verifier":verifier}))
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let export = f.st.repo.account_export(&attacker.user.tenant_id, &attacker.user.user_id, true).await.unwrap();
        assert!(export["federated_identities"].as_array().unwrap().is_empty());
    }
    let b = begin(&f, Some(&victim.access_token)).await;
    let linked = finish_browser(&f, &b, "victim-provider", json!({"email":null}), None).await;
    assert_eq!(linked["user"]["user_id"], victim.user.user_id);
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_consumed_handoff_and_authenticated_refresh_cannot_cross_revocation() {
    use memoswish_auth::oidc::digest;
    use memoswish_core::identity::LoginHandoff;
    let f = fixture("apple").await;
    let b = begin(&f, None).await;
    let auth = finish_browser(&f, &b, "barrier-sub", json!({}), None).await;
    let jwt = auth["access_token"].as_str().unwrap();
    let principal = f.st.services.auth.authenticate(Some(jwt)).await.unwrap();
    let h = LoginHandoff {
        attempt_id: None,
        hash: digest("handoff-before-revoke"),
        provider: "test".into(),
        tenant_id: principal.tenant_id.clone(),
        user_id: principal.user_id.clone(),
        challenge: challenge(VERIFIER),
        expires_at: now() + 60,
        generation: principal.auth_generation.unwrap(),
        pending_identity: None,
        link_session_hash: None,
    };
    f.st.repo.identity_handoff_insert(&h).await.unwrap();
    let consumed = f.st.repo.identity_handoff_consume(&h.hash, "test", &h.challenge, now()).await.unwrap().unwrap();
    let ready = Arc::new(tokio::sync::Barrier::new(2));
    let revoked = Arc::new(tokio::sync::Barrier::new(2));
    let task = {
        let (ready, revoked) = (ready.clone(), revoked.clone());
        let service = f.st.services.auth.clone();
        let repo = f.st.repo.clone();
        let principal = principal.clone();
        tokio::spawn(async move {
            ready.wait().await;
            revoked.wait().await;
            assert!(service.refresh(&principal).await.is_err());
            let user = repo.get_user(&consumed.tenant_id, &consumed.user_id).await.unwrap().unwrap();
            assert!(service.interactive_response_at_generation(&user, consumed.generation).await.is_err());
            // 模拟回调已解析身份，但直到通知提交后才插入 handoff。
            repo.identity_handoff_insert(&consumed).await.unwrap();
        })
    };
    ready.wait().await;
    f.st.repo
        .identity_event("https://appleid.apple.com", "barrier-sub", "barrier-event", "consent-revoked", now(), now())
        .await
        .unwrap();
    revoked.wait().await;
    task.await.unwrap();
    assert_eq!(
        send(
            &f.app,
            "POST",
            "/v1/auth/oidc/test/complete",
            None,
            None,
            Some(json!({"code":"handoff-before-revoke","code_verifier":VERIFIER}))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert!(f.st.services.auth.authenticate(Some(jwt)).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_jwks_expired_cache_fetches_once_per_validation_and_fails_closed() {
    let f = fixture("generic").await;
    f.m.ttl.store(0, Ordering::SeqCst);
    let svc = f.st.oidc.as_ref().unwrap();
    let c = claims(&f.m.issuer, "nonce", "sub");
    let unknown = signed(&c, &ROTATED, false);
    for expected in 1..=3 {
        assert!(svc.validate_id_token("test", &unknown, "nonce", "browser-client").await.is_err());
        assert_eq!(
            f.m.fetches.load(Ordering::SeqCst),
            expected,
            "freshness fetch cannot be followed by a rotation fetch"
        );
    }
    // 先在新鲜缓存上触发强制轮换，再令轮换结果立即过期。
    let f = fixture("generic").await;
    let svc = f.st.oidc.as_ref().unwrap();
    let c = claims(&f.m.issuer, "nonce", "sub");
    svc.validate_id_token("test", &signed(&c, &KEYS, false), "nonce", "browser-client").await.unwrap();
    f.m.ttl.store(0, Ordering::SeqCst);
    for expected in 2..=4 {
        assert!(svc.validate_id_token("test", &signed(&c, &ROTATED, false), "nonce", "browser-client").await.is_err());
        assert_eq!(f.m.fetches.load(Ordering::SeqCst), expected);
    }
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_identity_management_requires_app_session_recent_auth_and_preserves_last_login() {
    let f = fixture("generic").await;
    let b = begin(&f, None).await;
    let social = finish_browser(&f, &b, "social-only", json!({}), None).await;
    let jwt = social["access_token"].as_str().unwrap();
    let path = "/v1/account/identities";
    assert_eq!(send(&f.app, "GET", path, None, None, None).await.0, StatusCode::UNAUTHORIZED);
    let (status, headers, identities) = send(&f.app, "GET", path, Some(jwt), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(identities[0]["provider"], "test");
    assert!(!identities.to_string().contains("credential"));
    assert_eq!(
        send(&f.app, "DELETE", "/v1/account/identities/test", Some(jwt), None, None).await.0,
        StatusCode::CONFLICT
    );
    let existing =
        f.st.services
            .auth
            .register(&RegisterRequest {
                email: "password@example.com".into(),
                password: "password123".into(),
                display_name: "Password".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let b = begin(&f, Some(&existing.access_token)).await;
    finish_browser(&f, &b, "linked", json!({"email":"password@example.com"}), None).await;
    let p = f.st.services.auth.authenticate(Some(&existing.access_token)).await.unwrap();
    let api = f.st.services.auth.create_api_token(&p, "agent", vec!["*".into()], None).await.unwrap();
    assert_eq!(send(&f.app, "GET", path, Some(&api.plaintext), None, None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        send(&f.app, "DELETE", "/v1/account/identities/test", Some(&api.plaintext), None, None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&f.app, "DELETE", "/v1/account/identities/test", Some(&existing.access_token), None, None).await.0,
        StatusCode::NO_CONTENT
    );
    let (_, _, identities) = send(&f.app, "GET", path, Some(&existing.access_token), None, None).await;
    assert!(identities.as_array().unwrap().is_empty());
    let b = begin(&f, Some(&existing.access_token)).await;
    finish_browser(&f, &b, "linked-again", json!({"email":"password@example.com"}), None).await;
    let db = memoswish_storage::sqlite::SqliteRepository::connect(&f.st.config.database_url()).await.unwrap();
    sqlx::query("UPDATE recent_authentication SET expires_at=0").execute(db.pool()).await.unwrap();
    let refreshed = f.st.services.auth.refresh(&p).await.unwrap();
    assert_eq!(
        send(&f.app, "DELETE", "/v1/account/identities/test", Some(&refreshed.access_token), None, None).await.0,
        StatusCode::FORBIDDEN
    );
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_apple_unlink_persists_revocation_without_erasing_account() {
    let mut f = fixture("apple").await;
    let account =
        f.st.services
            .auth
            .register(&RegisterRequest {
                email: "apple-unlink@example.com".into(),
                password: "password123".into(),
                display_name: "Owner".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let b = begin(&f, Some(&account.access_token)).await;
    finish_browser(&f, &b, "apple-linked", json!({"email":"apple-unlink@example.com"}), None).await;
    *f.m.mode.lock().unwrap() = "revoke-fail".into();
    assert_eq!(
        send(&f.app, "DELETE", "/v1/account/identities/test", Some(&account.access_token), None, None).await.0,
        StatusCode::ACCEPTED
    );
    let jobs = f.st.repo.account_erasure_jobs().await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(!jobs[0].purge_assets);
    crate::account_tests::erasure_retry_due_for_test(&f.st, &jobs[0]).await;
    assert!(super::account::finish(&f.st, &jobs[0]).await.is_err());
    let mut disabled = f.st.config.as_ref().clone();
    disabled.oidc.enabled = false;
    let without_oidc = AppState::build(disabled).await.unwrap();
    assert_eq!(without_oidc.repo.account_erasure_jobs().await.unwrap().len(), 1);
    crate::account_tests::erasure_retry_due_for_test(&without_oidc, &jobs[0]).await;
    assert!(super::account::finish(&without_oidc, &jobs[0]).await.is_err());
    crate::runtime::drain_test_state(&without_oidc).await;
    *f.m.mode.lock().unwrap() = String::new();
    crate::account_tests::erasure_retry_due_for_test(&f.st, &jobs[0]).await;
    crate::maintenance_scheduler::due_for_test(&f.st.config).await.unwrap();
    crate::runtime::drain_test_state(&f.st).await;
    f.st = AppState::build(f.st.config.as_ref().clone()).await.unwrap();
    // 缺提供者的一页已推进游标；下一到期周期仍须使用原业务重试预算完成撤销。
    super::account::cleanup(&f.st).await.unwrap();
    f.app = super::api::router(f.st.clone());
    assert!(f.st.repo.account_erasure_jobs().await.unwrap().is_empty());
    assert!(f.m.revocations.load(Ordering::SeqCst) > 0);
    assert_eq!(send(&f.app, "GET", "/v1/me", Some(&account.access_token), None, None).await.0, StatusCode::OK);
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_unlink_invalidates_pending_login_link_and_previously_started_callback() {
    let f = fixture("generic").await;
    let account =
        f.st.services
            .auth
            .register(&RegisterRequest {
                email: "unlink-fence@example.com".into(),
                password: "password123".into(),
                display_name: "Owner".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let linking = begin(&f, Some(&account.access_token)).await;
    finish_browser(&f, &linking, "unlink-subject", json!({}), None).await;
    let pending = begin(&f, None).await;
    let code = upstream(&f, &pending, "unlink-subject", json!({}));
    let (s, headers, _) = callback(&f, &pending, &code, None, Some(&pending.cookie)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let target = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    let handoff = target.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
    let unfinished = begin(&f, None).await;
    let late_code = upstream(&f, &unfinished, "unlink-subject", json!({}));
    let pending_link = begin(&f, Some(&account.access_token)).await;
    let link_code = upstream(&f, &pending_link, "unlink-subject", json!({}));
    assert_eq!(
        send(&f.app, "DELETE", "/v1/account/identities/test", Some(&account.access_token), None, None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(
            &f.app,
            "POST",
            "/v1/auth/oidc/test/complete",
            None,
            None,
            Some(json!({"code":handoff,"code_verifier":VERIFIER}))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(callback(&f, &unfinished, &late_code, None, Some(&unfinished.cookie)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        callback(&f, &pending_link, &link_code, None, Some(&pending_link.cookie)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(send(&f.app, "GET", "/v1/me", Some(&account.access_token), None, None).await.0, StatusCode::OK);
    assert_eq!(
        send(&f.app, "GET", "/v1/account/identities", Some(&account.access_token), None, None).await.2,
        json!([])
    );
    // 新的显式交互关联可以重新添加已解绑身份。
    let fresh = begin(&f, Some(&account.access_token)).await;
    finish_browser(&f, &fresh, "unlink-subject", json!({}), None).await;
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_unlink_invalidates_alias_handoffs_callbacks_and_deferred_links() {
    let f = fixture_with_alias("generic", true).await;
    let account =
        f.st.services
            .auth
            .register(&RegisterRequest {
                email: "alias-unlink@example.com".into(),
                password: "password123".into(),
                display_name: "Owner".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let linking = begin(&f, Some(&account.access_token)).await;
    finish_browser(&f, &linking, "alias-subject", json!({}), None).await;
    let login = begin_provider(&f, "alias", None).await;
    let auth = finish_browser(&f, &login, "alias-subject", json!({}), None).await;
    assert_eq!(auth["user"]["user_id"], account.user.user_id);
    let unresolved = begin_provider(&f, "alias", None).await;
    let late_code = upstream(&f, &unresolved, "alias-subject", json!({}));
    let mut handoffs = Vec::new();
    for link in [None, Some(account.access_token.as_str())] {
        let browser = begin_provider(&f, "alias", link).await;
        let code = upstream(&f, &browser, "alias-subject", json!({}));
        let (status, headers, body) = callback(&f, &browser, &code, None, Some(&browser.cookie)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        let target = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
        let handoff = target.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
        handoffs.push((handoff, link));
    }
    assert_eq!(
        send(&f.app, "DELETE", "/v1/account/identities/test", Some(&account.access_token), None, None).await.0,
        StatusCode::NO_CONTENT
    );
    for (handoff, link) in handoffs {
        let (status, _, body) = send(
            &f.app,
            "POST",
            "/v1/auth/oidc/alias/complete",
            link,
            None,
            Some(json!({"code":handoff,"code_verifier":VERIFIER})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body.get("access_token").is_none());
    }
    assert_eq!(callback(&f, &unresolved, &late_code, None, Some(&unresolved.cookie)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(&f.app, "GET", "/v1/account/identities", Some(&account.access_token), None, None).await.2,
        json!([])
    );
    assert_eq!(send(&f.app, "GET", "/v1/me", Some(&account.access_token), None, None).await.0, StatusCode::OK);
    let fresh = begin_provider(&f, "alias", Some(&account.access_token)).await;
    finish_browser(&f, &fresh, "alias-subject", json!({}), None).await;
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_alias_complete_rechecks_canonical_identity_in_completion_transaction() {
    for case in ["missing", "reassigned", "legacy", "fenced"] {
        let f = fixture_with_alias("generic", true).await;
        let first = begin(&f, None).await;
        let account = finish_browser(&f, &first, "canonical-subject", json!({}), None).await;
        let alias = begin_provider(&f, "alias", None).await;
        let code = upstream(&f, &alias, "canonical-subject", json!({}));
        let (status, headers, _) = callback(&f, &alias, &code, None, Some(&alias.cookie)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let target = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
        let handoff = target.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
        let db = memoswish_storage::sqlite::SqliteRepository::connect(&f.st.config.database_url()).await.unwrap();
        // 保留 handoff 和 attempt，单独验证完成事务的身份归属与序列屏障。
        match case {
            "missing" => {
                sqlx::query("DELETE FROM federated_identities").execute(db.pool()).await.unwrap();
            }
            "reassigned" => {
                let other =
                    f.st.services
                        .auth
                        .register(&RegisterRequest {
                            email: "other-alias@example.com".into(),
                            password: "password123".into(),
                            display_name: "Other".into(),
                            tenant_name: None,
                        })
                        .await
                        .unwrap();
                sqlx::query("UPDATE federated_identities SET tenant_id=$1,user_id=$2")
                    .bind(other.user.tenant_id)
                    .bind(other.user.user_id)
                    .execute(db.pool())
                    .await
                    .unwrap();
            }
            "legacy" => {
                sqlx::query("UPDATE oidc_attempts SET identity_issuer=NULL,identity_subject=NULL")
                    .execute(db.pool())
                    .await
                    .unwrap();
            }
            "fenced" => {
                let hash = memoswish_core::ids::sha256_hex(format!("{}\0canonical-subject", f.m.issuer).as_bytes());
                sqlx::query("INSERT INTO identity_unlink_fences(identity_hash,sequence) SELECT $1,value FROM oidc_sequence WHERE id=1")
                    .bind(hash).execute(db.pool()).await.unwrap();
            }
            _ => unreachable!(),
        }
        sqlx::query("DELETE FROM recent_authentication").execute(db.pool()).await.unwrap();
        let (status, _, body) = send(
            &f.app,
            "POST",
            "/v1/auth/oidc/alias/complete",
            None,
            None,
            Some(json!({"code":handoff,"code_verifier":VERIFIER})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}: {body}");
        assert!(body.get("access_token").is_none());
        let recent: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM recent_authentication").fetch_one(db.pool()).await.unwrap();
        assert_eq!(recent, 0, "{case} cannot register interactive authentication");
        assert_eq!(send(&f.app, "GET", "/v1/me", account["access_token"].as_str(), None, None).await.0, StatusCode::OK);
        f.cleanup().await;
    }
}

#[tokio::test]
async fn oidc_return_allowlist_requires_authority_free_private_scheme() {
    let f = fixture("generic").await;
    for uri in ["com.memoswish.app:/auth/callback", "https://app.example/auth/callback"] {
        let mut config = f.st.config.oidc.clone();
        config.return_uris = vec![uri.into()];
        config.validate().unwrap();
    }
    for uri in [
        "com.memoswish.app://auth/callback",
        "com.memoswish.app:///auth/callback",
        "com.memoswish.app:auth/callback",
        "custom:/auth/callback",
        "http://app.example/auth/callback",
        "javascript:alert(1)",
        "com.memoswish.app:/auth/callback?code=x",
        "com.memoswish.app:/auth/callback#x",
    ] {
        let mut config = f.st.config.oidc.clone();
        config.return_uris = vec![uri.into()];
        assert!(config.validate().is_err(), "unsafe return URI accepted: {uri}");
        let mut request = start_request(false);
        request["return_uri"] = json!(uri);
        assert_eq!(
            send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(request)).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_zero_membership_browser_and_native_account_sessions() {
    oidc_zero_membership_case(false, None).await;
}

#[tokio::test]
async fn oidc_account_survives_s5_workspace_deletion() {
    oidc_zero_membership_case(true, None).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_oidc_account_survives_s5_workspace_deletion() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        oidc_zero_membership_case(true, Some(url)).await;
        database.cleanup().await;
    });
}

async fn oidc_zero_membership_case(delete_workspace: bool, database_url: Option<String>) {
    let f = fixture_with_database("generic", false, database_url).await;
    let b = begin(&f, None).await;
    let initial = finish_browser(&f, &b, "account-only", json!({}), None).await;
    let tenant = initial["user"]["tenant_id"].as_str().unwrap();
    let user = initial["user"]["user_id"].as_str().unwrap();
    if delete_workspace {
        let owner = memoswish_core::repo::UserRecord {
            id: memoswish_core::ids::new_id(),
            tenant_id: tenant.into(),
            email: "s5-deleter@example.com".into(),
            display_name: "Workspace owner".into(),
            password_hash: String::new(),
            role: memoswish_core::Role::Owner,
            created_at: chrono::Utc::now(),
        };
        f.st.repo.insert_user(&owner).await.unwrap();
        let session = f.st.services.auth.interactive_response(&owner).await.unwrap();
        let p = f.st.services.auth.authenticate(Some(&session.access_token)).await.unwrap();
        f.st.services
            .delete_workspace(&p, &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: tenant.into() })
            .await
            .unwrap();
        assert!(f.st.repo.get_tenant(tenant).await.unwrap().is_none());
        assert!(f.st.repo.account_by_id(&owner.id).await.unwrap().is_some());
    } else {
        f.st.repo.membership_remove(tenant, user).await.unwrap();
    }
    let b = begin(&f, None).await;
    let code = upstream(&f, &b, "account-only", json!({}));
    let (status, headers, _) = callback(&f, &b, &code, None, Some(&b.cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let url = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    let handoff = url.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
    let req = json!({"code":handoff,"code_verifier":VERIFIER});
    let (status, headers, account) =
        send(&f.app, "POST", "/v1/auth/account-sessions/oidc/test/complete", None, None, Some(req.clone())).await;
    assert_eq!(status, StatusCode::OK, "{account}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(account["account"]["user_id"], user);
    assert!(account["account"].get("tenant_id").is_none());
    assert!(f.st.repo.memberships(user).await.unwrap().is_empty());
    assert!(f.st.repo.get_user(memoswish_core::ids::LOCAL_TENANT_ID, user).await.unwrap().is_none());
    for (method, path) in [("GET", "/v1/account/empty/export"), ("POST", "/v1/auth/account-sessions/refresh")] {
        assert_eq!(send(&f.app, method, path, account["access_token"].as_str(), None, None).await.0, StatusCode::OK);
    }
    assert_eq!(
        send(&f.app, "GET", "/v1/account/profile", account["access_token"].as_str(), None, None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&f.app, "GET", "/v1/me", account["access_token"].as_str(), None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/account-sessions/oidc/test/complete", None, None, Some(req)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, a) = send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(start_request(true))).await;
    assert_eq!(status, StatusCode::OK);
    let mut c = claims(&f.m.issuer, a["nonce"].as_str().unwrap(), "account-only");
    c["aud"] = json!("native-client");
    let req = json!({"attempt_id":a["attempt_id"],"id_token":signed(&c,&KEYS,false),"nonce":a["nonce"],"code_verifier":VERIFIER});
    let (status, _, native) =
        send(&f.app, "POST", "/v1/auth/account-sessions/oidc/test/exchange", None, None, Some(req.clone())).await;
    assert_eq!(status, StatusCode::OK, "{native}");
    assert_eq!(native["account"]["user_id"], user);
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/account-sessions/oidc/test/exchange", None, None, Some(req)).await.0,
        StatusCode::UNAUTHORIZED
    );
    crate::account_tests::assert_erasure_response(
        &f.st,
        send(&f.app, "DELETE", "/v1/account/empty", native["access_token"].as_str(), None, None).await.0,
    )
    .await;
    f.cleanup().await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn feature_matrix_postgres_http_authorization_and_restart() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        browser_replay_case(fixture_with_database("generic", false, Some(url)).await).await;
        database.cleanup().await;
    });
}

#[cfg(feature = "mcp-oauth")]
#[tokio::test]
async fn both_auth_capabilities_work_for_free_tenant_without_selecting_paid_policy() {
    let mut f = fixture("generic").await;
    let mut cfg = f.st.config.as_ref().clone();
    cfg.default_plan = "free".into();
    cfg.oauth = memoswish_auth::oauth_config::OAuthConfig {
        enabled: true,
        issuer: "https://learn.example".into(),
        public_base_url: "https://learn.example".into(),
        mcp_resource: "https://learn.example/mcp".into(),
        ..Default::default()
    };
    crate::runtime::drain_test_state(&f.st).await;
    f.st = AppState::build(cfg).await.unwrap();
    f.app = super::api::router(f.st.clone());
    assert!(f.st.oauth.is_some() && f.st.oidc.is_some());
    let (status, headers, _) = send(&f.app, "GET", "/.well-known/oauth-authorization-server", None, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let b = begin(&f, None).await;
    let auth = finish_browser(&f, &b, "free-tenant", json!({}), None).await;
    let p = f.st.services.auth.authenticate(auth["access_token"].as_str()).await.unwrap();
    let before = f.st.services.quota.snapshot(&p).await.unwrap();
    assert_eq!(before.plan, "free");
    let result = f.st.services.quota.consume(&p, memoswish_auth::Metric::McpCalls, 1_001).await;
    let after = f.st.services.quota.snapshot(&p).await.unwrap();
    let calls = after.metrics.iter().find(|m| m.metric == "mcp_calls").unwrap();
    if cfg!(feature = "commercial-quota") {
        assert!(matches!(result, Err(memoswish_core::CoreError::QuotaExceeded(_))));
        assert_eq!(calls.limit, Some(1_000));
        assert_eq!(calls.used, 0);
    } else {
        result.unwrap();
        assert_eq!(calls.limit, None);
        assert_eq!(calls.used, 1_001);
    }
    f.cleanup().await;
}

#[tokio::test]
async fn oidc_opaque_completion_and_resumable_key_rotation() {
    use memoswish_auth::token::VerificationKey;
    let f = fixture("generic").await;
    let b = begin(&f, None).await;
    // 在 launch 与 callback 之间换 active key，已有 attempt 仍可继续。
    let mut config = (*f.st.config).clone();
    config
        .oidc
        .encryption_keys
        .insert("legacy".into(), VerificationKey { secret: config.oidc.encryption_key.clone(), verify_until: None });
    config
        .oidc
        .encryption_keys
        .insert("next".into(), VerificationKey { secret: URL_SAFE_NO_PAD.encode([9; 32]), verify_until: None });
    config.oidc.encryption_key_id = "next".into();
    let service = memoswish_auth::oidc::OidcService::new(
        config.oidc.clone(),
        f.st.repo.clone(),
        f.st.services.auth.clone(),
        "free".into(),
    )
    .unwrap();
    assert!(service.reencrypt().await.unwrap() > 0);
    assert_eq!(service.reencrypt().await.unwrap(), 0);
    // 新服务实例只保留新 key，证明旧 attempt 已被实际迁移。
    config.oidc.encryption_keys.remove("legacy");
    config.oidc.encryption_key.clear();
    crate::runtime::drain_test_state(&f.st).await;
    let restarted = AppState::build(config).await.unwrap();
    let app = crate::auth_defenses::test_router(restarted.clone());
    let code = upstream(&f, &b, "opaque-oidc-user", json!({}));
    let params = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", &query(&b, "state"))
        .append_pair("code", &code)
        .finish();
    let (status, headers, body) =
        send(&app, "GET", &format!("/v1/auth/oidc/test/callback?{params}"), None, Some(&b.cookie), None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let target = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    let handoff = target.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
    let req = json!({"code":handoff,"code_verifier":VERIFIER});
    let (status, _, body) =
        send(&app, "POST", "/v1/auth/sessions/oidc/test/complete", None, None, Some(req.clone())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].as_str().unwrap().starts_with("lts_at_"));
    assert!(body["refresh_token"].as_str().unwrap().starts_with("lts_rt_"));
    assert!(restarted.services.auth.authenticate_account(body["access_token"].as_str().unwrap()).await.is_ok());
    let (status, _, _) = send(&app, "POST", "/v1/auth/sessions/oidc/test/complete", None, None, Some(req)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    crate::runtime::drain_test_state(&restarted).await;
    f.cleanup().await;
}

#[tokio::test]
async fn s21b_link_completion_profiles_obey_logout_ordering() {
    let f = fixture("generic").await;
    for legacy in [true, false] {
        for profile in ["workspace", "account", "opaque", "ack"] {
            if legacy && profile == "ack" {
                continue;
            }
            for logout_first in [true, false] {
                let email = format!("{legacy}-{profile}-{logout_first}@example.com");
                let registered =
                    f.st.services
                        .auth
                        .register(&RegisterRequest {
                            email: email.clone(),
                            password: "password123".into(),
                            display_name: "Link ordering".into(),
                            tenant_name: None,
                        })
                        .await
                        .unwrap();
                let root =
                    f.st.services
                        .auth
                        .login_session(&LoginRequest { email, password: "password123".into() })
                        .await
                        .unwrap();
                let tenant = &registered.user.tenant_id;
                let workspace = f.st.services.auth.select_session_workspace(&root.access_token, tenant).await.unwrap();
                let bearer = if legacy { &registered.access_token } else { &workspace.access_token };
                let principal = f.st.services.auth.authenticate(Some(bearer)).await.unwrap();
                let api =
                    f.st.services
                        .auth
                        .create_api_token(&principal, "Independent API", vec!["*".into()], None)
                        .await
                        .unwrap();
                let browser = begin(&f, Some(bearer)).await;
                let code = upstream(&f, &browser, &format!("{legacy}-{profile}-{logout_first}"), json!({"email":null}));
                let (status, headers, body) = callback(&f, &browser, &code, None, Some(&browser.cookie)).await;
                assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
                let target = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
                let handoff = target.query_pairs().find(|(key, _)| key == "code").unwrap().1.into_owned();
                let path = match profile {
                    "workspace" => "/v1/auth/oidc/test/complete",
                    "account" => "/v1/auth/account-sessions/oidc/test/complete",
                    "opaque" => "/v1/auth/sessions/oidc/test/complete",
                    _ => "/v1/auth/sessions/oidc/test/link/complete",
                };
                let before = f.st.services.auth.list_sessions(&root.access_token).await.unwrap();
                if logout_first {
                    f.st.services.auth.logout_everywhere(&root.access_token).await.unwrap();
                }
                let (status, headers, body) = send(
                    &f.app,
                    "POST",
                    path,
                    Some(bearer),
                    None,
                    Some(json!({"code":handoff,"code_verifier":VERIFIER})),
                )
                .await;
                let identities = f.st.repo.identity_list(tenant, &root.account.user_id).await.unwrap();
                if logout_first {
                    assert_eq!(status, StatusCode::UNAUTHORIZED, "legacy={legacy} profile={profile}: {body}");
                    assert!(identities.is_empty());
                } else {
                    assert_eq!(
                        status,
                        if profile == "ack" { StatusCode::NO_CONTENT } else { StatusCode::OK },
                        "legacy={legacy} profile={profile}: {body}"
                    );
                    assert_eq!(identities.len(), 1);
                    let issued = match profile {
                        "workspace" => Some(serde_json::from_value::<AuthResponse>(body).unwrap().access_token),
                        "account" => Some(serde_json::from_value::<AccountSessionResponse>(body).unwrap().access_token),
                        "opaque" => Some(serde_json::from_value::<SessionResponse>(body).unwrap().access_token),
                        _ => None,
                    };
                    let after = f.st.services.auth.list_sessions(&root.access_token).await.unwrap();
                    assert_eq!(after.len(), before.len() + usize::from(profile == "opaque"));
                    f.st.services.auth.logout_everywhere(&root.access_token).await.unwrap();
                    if let Some(issued) = issued {
                        if profile == "account" || profile == "opaque" {
                            assert!(f.st.services.auth.authenticate_account(&issued).await.is_err());
                        } else {
                            assert!(f.st.services.auth.authenticate(Some(&issued)).await.is_err());
                        }
                    }
                }
                assert_eq!(headers[header::CACHE_CONTROL], "no-store");
                assert!(f.st.services.auth.authenticate(Some(&api.plaintext)).await.is_ok());
            }
        }
    }
    f.task.abort();

    f.cleanup().await;
}

#[tokio::test]
async fn s21b_link_ack_preserves_session_and_rejects_wrong_bindings() {
    let f = fixture("generic").await;
    let registered =
        f.st.services
            .auth
            .register_session(&RegisterRequest {
                email: "ack@example.com".into(),
                password: "password123".into(),
                display_name: "ACK".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let tenant = f.st.services.auth.session_memberships(&registered.access_token).await.unwrap()[0].tenant_id.clone();
    for negative in ["success", "provider", "verifier", "session", "refresh", "logout", "login"] {
        let root =
            f.st.services
                .auth
                .login_session(&LoginRequest { email: "ack@example.com".into(), password: "password123".into() })
                .await
                .unwrap();
        let workspace = f.st.services.auth.select_session_workspace(&root.access_token, &tenant).await.unwrap();
        let access = &workspace.access_token;
        let before = f.st.repo.session_access(&memoswish_auth::sessions::access_hash(access).unwrap()).await.unwrap();
        let families = f.st.services.auth.list_sessions(access).await.unwrap();
        let identities = f.st.repo.identity_list(&tenant, &root.account.user_id).await.unwrap();
        let browser = begin(&f, if negative == "login" { None } else { Some(access) }).await;
        let code = upstream(&f, &browser, &format!("ack-{negative}"), json!({}));
        let (status, headers, body) = callback(&f, &browser, &code, None, Some(&browser.cookie)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        let target = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
        let handoff = target.query_pairs().find(|(key, _)| key == "code").unwrap().1.into_owned();
        let req = json!({"code":handoff,"code_verifier":if negative=="verifier" {"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"} else {VERIFIER}});
        let other = f.st.services.auth.select_session_workspace(&root.access_token, &tenant).await.unwrap();
        let path = if negative == "provider" {
            "/v1/auth/sessions/oidc/unknown/link/complete"
        } else {
            "/v1/auth/sessions/oidc/test/link/complete"
        };
        if negative == "refresh" {
            f.st.services.auth.refresh_session(&workspace.refresh_token).await.unwrap();
        }
        if negative == "logout" {
            f.st.services.auth.logout_everywhere(&root.access_token).await.unwrap();
        }
        let (status, headers, body) = send(
            &f.app,
            "POST",
            path,
            Some(if negative == "session" { &other.access_token } else { access }),
            None,
            Some(req.clone()),
        )
        .await;
        if negative == "success" {
            assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
            let after =
                f.st.repo.session_access(&memoswish_auth::sessions::access_hash(access).unwrap()).await.unwrap();
            assert_eq!(before.family, after.family);
            assert_eq!(before.credential, after.credential);
            assert_eq!(families, f.st.services.auth.list_sessions(access).await.unwrap());
            assert_eq!(
                f.st.repo.identity_list(&tenant, &root.account.user_id).await.unwrap().len(),
                identities.len() + 1
            );
            assert!(send(&f.app, "POST", path, Some(access), None, Some(req)).await.0.is_client_error());
            assert!(f.st.services.auth.refresh_session(&workspace.refresh_token).await.is_ok());
        } else {
            assert!(status.is_client_error(), "{negative}: {status} {body}");
            assert_eq!(
                serde_json::to_value(f.st.repo.identity_list(&tenant, &root.account.user_id).await.unwrap()).unwrap(),
                serde_json::to_value(&identities).unwrap()
            );
        }
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
    f.cleanup().await;
}

#[path = "tests/privacy_oidc.rs"]
mod privacy_oidc;
