//! 资料库 HTTP 适配器，业务与事务保持在应用门面。
use crate::{
    api::{ApiResult, Auth},
    app::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use memoswish_protocol::*;
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/library", get(library))
        .route("/v1/history", get(history))
        .route("/v1/library/{card_id}/favorite", post(favorite))
}
async fn library(
    State(s): State<AppState>,
    Auth(p): Auth,
    q: Result<Query<LibraryQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<LibraryPage>> {
    let Query(q) = q.map_err(|_| memoswish_core::CoreError::invalid("invalid library query"))?;
    Ok(Json(s.services.library_page(&p, &q).await?))
}
async fn history(
    State(s): State<AppState>,
    Auth(p): Auth,
    q: Result<Query<LibraryQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<ReviewHistoryPage>> {
    let Query(q) = q.map_err(|_| memoswish_core::CoreError::invalid("invalid history query"))?;
    Ok(Json(s.services.review_history(&p, &q).await?))
}
async fn favorite(
    State(s): State<AppState>,
    Auth(p): Auth,
    Path(card): Path<String>,
    body: Result<Json<FavoriteCommand>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<FavoriteState>> {
    let Json(c) = body.map_err(|_| memoswish_core::CoreError::invalid("invalid favorite command"))?;
    Ok(Json(s.services.set_favorite(&p, &card, &c).await?))
}
