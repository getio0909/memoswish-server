//! 公共政策可在登录前读取，更新不接受目标用户或目标租户参数。
use crate::{
    api::{ApiResult, Auth},
    app::AppState,
};
use axum::{Json, Router, extract::State, routing::get};
use memoswish_protocol::{PrivacyPolicy, PrivacyState, PrivacyUpdate};
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/privacy/policy", get(policy))
        .route("/v1/privacy/state", get(state).post(update))
        .layer(axum::middleware::from_fn(no_store))
}
async fn policy(State(st): State<AppState>) -> Json<PrivacyPolicy> {
    Json(st.services.auth.privacy_policy().clone())
}
async fn state(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<Json<PrivacyState>> {
    Ok(Json(st.services.privacy_state(&p).await?))
}
async fn update(
    State(st): State<AppState>,
    Auth(p): Auth,
    body: Result<Json<PrivacyUpdate>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<PrivacyState>> {
    let Json(update) = body.map_err(|_| memoswish_core::CoreError::invalid("invalid privacy update"))?;
    Ok(Json(st.services.update_privacy(&p, &update).await?))
}

async fn no_store(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}
