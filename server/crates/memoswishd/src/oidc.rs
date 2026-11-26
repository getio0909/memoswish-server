//! OIDC HTTP 边界，回调只携带一次性 handoff，凭据响应禁止缓存。
use crate::api::{ApiErr, ApiResult};
use axum::{
    Json, Router,
    body::Bytes,
    extract::Request,
    extract::{DefaultBodyLimit, Path, RawQuery, State},
    http::{HeaderMap, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use memoswish_auth::{
    oidc::OidcService,
    oidc::{digest, secret},
};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::*;
use std::sync::Arc;

/// 参考条件：feature oidc，mode = multi_tenant，oidc.enabled = true。
pub fn router(service: Arc<OidcService>) -> Router {
    Router::new()
        .route("/v1/account/identities", get(identities))
        .route("/v1/account/identities/{provider}", delete(unlink))
        .route("/v1/auth/oidc/{provider}/start", post(start).get(launch))
        .route("/v1/auth/oidc/{provider}/link/start", post(link))
        .route("/v1/auth/oidc/{provider}/callback", get(callback_get).post(callback_post))
        .route("/v1/auth/oidc/{provider}/events", post(events))
        .route("/v1/auth/account-sessions/oidc/{provider}/complete", post(complete_account))
        .route("/v1/auth/account-sessions/oidc/{provider}/exchange", post(exchange_account))
        .route("/v1/auth/sessions/oidc/{provider}/complete", post(complete_session))
        .route("/v1/auth/sessions/oidc/{provider}/link/complete", post(complete_link_ack))
        .route("/v1/auth/sessions/oidc/{provider}/exchange", post(exchange_session))
        .route("/v1/auth/oidc/{provider}/complete", post(complete))
        .route("/v1/auth/oidc/{provider}/exchange", post(exchange))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(headers))
        .with_state(service)
}
fn app_jwt(h: &HeaderMap) -> CoreResult<&str> {
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| CoreError::Unauthorized("missing app session".into()))
}
async fn identities(State(s): State<Arc<OidcService>>, h: HeaderMap) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.linked_identities(app_jwt(&h)?).await?))
}
async fn unlink(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    h: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let pending = s.unlink_identity(&p, app_jwt(&h)?).await?;
    Ok(if pending { axum::http::StatusCode::ACCEPTED } else { axum::http::StatusCode::NO_CONTENT })
}
async fn headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    for (k, v) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("content-security-policy", "default-src 'none'; frame-ancestors 'none'"),
    ] {
        r.headers_mut().insert(k, v.parse().unwrap());
    }
    r
}
fn params(raw: Option<&str>) -> CoreResult<std::collections::HashMap<String, String>> {
    let raw = raw.unwrap_or("");
    if raw.len() > 16 * 1024 {
        return Err(CoreError::invalid("OIDC parameters exceed size limit"));
    }
    let mut out = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if out.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(CoreError::invalid("duplicate OIDC parameter"));
        }
    }
    Ok(out)
}
fn value<'a>(p: &'a std::collections::HashMap<String, String>, key: &str) -> CoreResult<&'a str> {
    p.get(key).map(String::as_str).filter(|s| !s.is_empty()).ok_or_else(|| CoreError::invalid("missing OIDC parameter"))
}
fn cookie_name(attempt: &str) -> String {
    format!("__Host-lti-{attempt}")
}
fn cookie(headers: &HeaderMap, name: &str) -> CoreResult<String> {
    let mut found = None;
    for raw in headers.get_all(header::COOKIE) {
        for pair in raw.to_str().unwrap_or("").split(';') {
            if let Some((k, v)) = pair.trim().split_once('=')
                && k == name
            {
                if found.is_some() {
                    return Err(CoreError::invalid("duplicate OIDC binding cookie"));
                }
                found = Some(v.to_string());
            }
        }
    }
    found.ok_or_else(|| CoreError::Unauthorized("missing OIDC browser binding".into()))
}
async fn start(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    Json(r): Json<OidcStartRequest>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.start(&p, &r, None).await?))
}
async fn link(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    h: HeaderMap,
    Json(r): Json<OidcStartRequest>,
) -> ApiResult<impl IntoResponse> {
    let jwt = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| CoreError::Unauthorized("missing app session".into()))?;
    Ok(Json(s.link_start(&p, &r, jwt).await?))
}
async fn launch(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    RawQuery(q): RawQuery,
) -> ApiResult<Response> {
    let q = params(q.as_deref())?;
    let attempt = value(&q, "attempt")?;
    let launch = value(&q, "launch")?;
    let browser = secret("")?;
    let target = s.launch(&p, attempt, launch, &browser).await?;
    let mut r = Redirect::to(&target).into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        format!("{}={browser}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=300", cookie_name(attempt))
            .parse()
            .map_err(|_| CoreError::invalid("invalid OIDC cookie"))?,
    );
    Ok(r)
}
async fn callback_get(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    h: HeaderMap,
    RawQuery(q): RawQuery,
) -> ApiResult<Response> {
    callback(s, p, h, params(q.as_deref())?).await
}
async fn callback_post(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    if !h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next() == Some("application/x-www-form-urlencoded"))
    {
        return Err(ApiErr(CoreError::invalid("expected form-encoded OIDC callback")));
    }
    let raw = std::str::from_utf8(&body).map_err(|_| CoreError::invalid("invalid OIDC callback encoding"))?;
    callback(s, p, h, params(Some(raw))?).await
}
async fn callback(
    s: Arc<OidcService>,
    p: String,
    h: HeaderMap,
    q: std::collections::HashMap<String, String>,
) -> ApiResult<Response> {
    s.limited("callback-lookup").await?;
    let state = value(&q, "state")?;
    let a = s
        .repo
        .identity_attempt(&digest(state), true)
        .await?
        .ok_or_else(|| CoreError::Unauthorized("unknown OIDC state".into()))?;
    let browser = cookie(&h, &cookie_name(&a.id))?;
    let target = s.callback(&p, state, &browser, value(&q, "code")?, q.get("user").map(String::as_str)).await?;
    let mut response = Redirect::to(&target).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{}=; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=0", cookie_name(&a.id))
            .parse()
            .map_err(|_| CoreError::invalid("invalid OIDC cookie"))?,
    );
    Ok(response)
}
async fn complete(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    h: HeaderMap,
    Json(r): Json<OidcCompleteRequest>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.complete(
            &p,
            &r,
            h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")),
        )
        .await?,
    ))
}
async fn exchange(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    Json(r): Json<OidcExchangeRequest>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.exchange(&p, &r).await?))
}

async fn events(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    Json(r): Json<serde_json::Value>,
) -> ApiResult<impl IntoResponse> {
    let payload = r["payload"].as_str().ok_or_else(|| CoreError::invalid("missing Apple event payload"))?;
    s.apple_event(&p, payload).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn complete_account(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    h: HeaderMap,
    body: Result<Json<OidcCompleteRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(r) = body.map_err(|_| CoreError::invalid("invalid account session request"))?;
    Ok(Json(
        s.complete_account(
            &p,
            &r,
            h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")),
        )
        .await?,
    ))
}
async fn exchange_account(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    body: Result<Json<OidcExchangeRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(r) = body.map_err(|_| CoreError::invalid("invalid account session request"))?;
    Ok(Json(s.exchange_account(&p, &r).await?))
}

async fn complete_session(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    h: HeaderMap,
    body: Result<Json<OidcCompleteRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(r) = body.map_err(|_| CoreError::invalid("invalid session request"))?;
    let bearer = h.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "));
    Ok(Json(s.complete_session(&p, &r, bearer).await?))
}
async fn exchange_session(
    State(s): State<Arc<OidcService>>,
    Path(p): Path<String>,
    body: Result<Json<OidcExchangeRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(r) = body.map_err(|_| CoreError::invalid("invalid session request"))?;
    Ok(Json(s.exchange_session(&p, &r).await?))
}

async fn complete_link_ack(
    State(s): State<Arc<OidcService>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Result<Json<OidcCompleteRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(request) = body.map_err(|_| CoreError::invalid("invalid link completion request"))?;
    s.complete_link_ack(&provider, &request, app_jwt(&headers)?).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
