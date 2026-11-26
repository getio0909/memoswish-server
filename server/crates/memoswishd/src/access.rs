//! 账户访问清单只接受第一方根会话；失败响应同样禁止缓存。
use crate::{
    api::{ApiErr, ApiResult},
    app::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use memoswish_core::{CoreError, CoreResult, session::AccessKind};
use serde::Deserialize;

#[derive(Default, Deserialize)]
struct PageQuery {
    after: Option<String>,
    limit: Option<u32>,
    tenant_id: Option<String>,
}
fn kind(s: &str) -> CoreResult<AccessKind> {
    match s {
        "sessions" => Ok(AccessKind::Sessions),
        "api-tokens" => Ok(AccessKind::ApiTokens),
        "grants" => Ok(AccessKind::Grants),
        _ => Err(CoreError::NotFound("access category".into())),
    }
}
fn bearer(h: &HeaderMap) -> CoreResult<&str> {
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")))
        .ok_or_else(|| CoreError::Unauthorized("account session required".into()))
}
fn query(q: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>) -> Result<PageQuery, ApiErr> {
    q.map(|Query(q)| q).map_err(|_| CoreError::invalid("invalid access query").into())
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/account/access/{kind}", get(list))
        .route("/v1/account/access/{kind}/{id}", axum::routing::delete(revoke))
        .layer(axum::middleware::from_fn(no_store))
}
async fn list(
    State(s): State<AppState>,
    h: HeaderMap,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    q: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<impl IntoResponse> {
    let Path(k) = path.map_err(|_| CoreError::invalid("invalid access path"))?;
    let q = query(q)?;
    Ok(Json(
        s.services
            .account_access(bearer(&h)?, kind(&k)?, q.after.as_deref().unwrap_or(""), q.limit.unwrap_or(50))
            .await?,
    ))
}
async fn revoke(
    State(s): State<AppState>,
    h: HeaderMap,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    q: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<StatusCode> {
    let Path((k, id)) = path.map_err(|_| CoreError::invalid("invalid access path"))?;
    let q = query(q)?;
    if !s.services.revoke_account_access(bearer(&h)?, kind(&k)?, q.tenant_id.as_deref(), &id).await? {
        return Err(CoreError::NotFound("access target".into()).into());
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn no_store(request: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut r = next.run(request).await;
    r.headers_mut().insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    r
}
