//! 私有学习控制端点沿用统一错误包络，不自动重试修改。
use crate::{
    api::{ApiResult, Auth},
    app::AppState,
};
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    routing::get,
};
use memoswish_core::CoreError;
use memoswish_protocol::*;
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/learning/preferences", get(preferences).post(retention))
        .route("/v1/learning/cards/{id}/control", get(control).post(set_control))
        .route("/v1/learning/hidden", get(hidden))
        .layer(axum::extract::DefaultBodyLimit::max(2048))
        .layer(axum::middleware::from_fn(no_store))
}
async fn no_store(request: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}
fn body<T>(v: Result<Json<T>, JsonRejection>) -> Result<T, CoreError> {
    v.map(|Json(v)| v).map_err(|_| CoreError::invalid("invalid learning control command"))
}
async fn preferences(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<Json<LearnerPreferences>> {
    Ok(Json(st.services.learner_preferences(&p).await?))
}
async fn retention(
    State(st): State<AppState>,
    Auth(p): Auth,
    v: Result<Json<RetentionCommand>, JsonRejection>,
) -> ApiResult<Json<LearnerPreferences>> {
    Ok(Json(st.services.set_retention(&p, &body(v)?).await?))
}
async fn control(
    State(st): State<AppState>,
    Auth(p): Auth,
    path: Result<Path<String>, PathRejection>,
) -> ApiResult<Json<LearnerCardControl>> {
    let Path(id) = path.map_err(|_| CoreError::invalid("invalid card control path"))?;
    Ok(Json(st.services.card_control(&p, &id).await?))
}
async fn set_control(
    State(st): State<AppState>,
    Auth(p): Auth,
    path: Result<Path<String>, PathRejection>,
    v: Result<Json<CardControlCommand>, JsonRejection>,
) -> ApiResult<Json<LearnerCardControl>> {
    let Path(id) = path.map_err(|_| CoreError::invalid("invalid card control path"))?;
    Ok(Json(st.services.set_card_control(&p, &id, &body(v)?).await?))
}
#[derive(serde::Deserialize)]
struct Page {
    after: Option<String>,
    limit: Option<u32>,
}
async fn hidden(
    State(st): State<AppState>,
    Auth(p): Auth,
    q: Result<Query<Page>, QueryRejection>,
) -> ApiResult<Json<HiddenCardsPage>> {
    let Query(q) = q.map_err(|_| CoreError::invalid("invalid hidden-card query"))?;
    Ok(Json(st.services.hidden_cards(&p, q.after.as_deref(), q.limit.unwrap_or(50)).await?))
}
