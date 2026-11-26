//! 账户口令端点；匿名请求保持通用确认，所有响应禁止缓存。
use crate::{
    api::{ApiErr, ApiResult},
    app::AppState,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::*;
fn bearer(headers: &HeaderMap) -> CoreResult<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| CoreError::Unauthorized("account session required".into()))
}
fn decode<T>(body: Result<Json<T>, axum::extract::rejection::JsonRejection>) -> Result<T, ApiErr> {
    body.map(|Json(v)| v).map_err(|_| CoreError::invalid("invalid password request").into())
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/password/verification", post(request_verification))
        .route("/v1/auth/password/verification/resend", post(request_verification))
        .route("/v1/auth/password/verification/confirm", post(verify))
        .route("/v1/auth/password/reset", post(request_reset))
        .route("/v1/auth/password/reset/confirm", post(reset))
        .route("/v1/account/password", get(status).post(change))
        .layer(axum::middleware::from_fn(no_store))
}
async fn request_verification(
    State(s): State<AppState>,
    body: Result<Json<PasswordVerificationRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.services.auth.request_password_verification(&decode(body)?).await?))
}
async fn request_reset(
    State(s): State<AppState>,
    body: Result<Json<PasswordEmailRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.services.auth.request_password_reset(&decode(body)?).await?))
}
async fn verify(
    State(s): State<AppState>,
    body: Result<Json<PasswordChallengeRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    s.services.auth.verify_password_email(&decode(body)?).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn reset(
    State(s): State<AppState>,
    body: Result<Json<PasswordResetRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    s.services.auth.reset_password(&decode(body)?).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn status(State(s): State<AppState>, h: HeaderMap) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.services.auth.password_status(bearer(&h)?).await?))
}
async fn change(
    State(s): State<AppState>,
    h: HeaderMap,
    body: Result<Json<PasswordChangeRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    s.services.auth.change_password(bearer(&h)?, &decode(body)?).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn no_store(request: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut r = next.run(request).await;
    r.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    r
}
