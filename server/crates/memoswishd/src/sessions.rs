//! 第一方 opaque 会话传输；所有成功响应禁止缓存，凭据错误沿用 REST envelope。
use crate::{
    api::{ApiErr, ApiResult},
    app::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::IntoResponse,
    routing::{delete, get, post},
};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::{LoginRequest, RegisterRequest, SessionRefreshRequest, WorkspaceSessionRequest};
fn bearer(h: &HeaderMap) -> CoreResult<&str> {
    h.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
        .ok_or_else(|| CoreError::Unauthorized("missing app session".into()))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/sessions", post(login).get(list).delete(logout_everywhere))
        .route("/v1/auth/sessions/register", post(register))
        .route("/v1/account/memberships", get(memberships))
        .route("/v1/auth/sessions/refresh", post(refresh))
        .route("/v1/auth/sessions/workspace", post(workspace))
        .route("/v1/auth/sessions/current", delete(logout))
        .route("/v1/auth/sessions/{session_id}", delete(revoke))
        .layer(axum::middleware::from_fn(no_store))
}
fn decode<T>(body: Result<Json<T>, axum::extract::rejection::JsonRejection>) -> Result<T, ApiErr> {
    body.map(|Json(v)| v).map_err(|_| CoreError::invalid("invalid session request").into())
}
async fn login(
    State(s): State<AppState>,
    body: Result<Json<LoginRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let r = decode(body)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(s.services.auth.login_session(&r).await?)))
}
async fn refresh(
    State(s): State<AppState>,
    body: Result<Json<SessionRefreshRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let r = decode(body)?;
    s.auth_limiter.check("session-refresh", 1.0).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(s.services.auth.refresh_session(&r.refresh_token).await?)))
}
async fn workspace(
    State(s): State<AppState>,
    h: HeaderMap,
    body: Result<Json<WorkspaceSessionRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let r = decode(body)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(s.services.auth.select_session_workspace(bearer(&h)?, &r.tenant_id).await?),
    ))
}
async fn list(State(s): State<AppState>, h: HeaderMap) -> ApiResult<impl IntoResponse> {
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(s.services.auth.list_sessions(bearer(&h)?).await?)))
}
async fn logout(State(s): State<AppState>, h: HeaderMap) -> ApiResult<impl IntoResponse> {
    s.services.auth.revoke_session(bearer(&h)?, None).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
async fn revoke(State(s): State<AppState>, h: HeaderMap, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    if !s.services.auth.revoke_session(bearer(&h)?, Some(&id)).await? {
        return Err(CoreError::NotFound("session".into()).into());
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn no_store(request: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}
async fn register(
    State(s): State<AppState>,
    body: Result<Json<RegisterRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let request = decode(body)?;
    Ok(Json(s.services.auth.register_session(&request).await?))
}
async fn memberships(State(s): State<AppState>, h: HeaderMap) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.services.auth.session_memberships(bearer(&h)?).await?))
}
async fn logout_everywhere(State(s): State<AppState>, h: HeaderMap) -> ApiResult<impl IntoResponse> {
    s.services.auth.logout_everywhere(bearer(&h)?).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
