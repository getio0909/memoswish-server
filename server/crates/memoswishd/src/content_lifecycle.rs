//! 严格编辑使用 POST 命令，统一 JSON 拒绝格式与私有缓存策略。
use crate::{
    api::{ApiResult, Auth},
    app::AppState,
};
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    routing::{get, post},
};
use memoswish_core::CoreError;
use memoswish_protocol::*;
use serde::Deserialize;
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/content/cards", post(save))
        .route("/v1/content/decks", post(create_deck))
        .route(
            "/v1/content/import/apkg",
            post(import_apkg).layer(axum::extract::DefaultBodyLimit::max(15 * 1024 * 1024)),
        )
        .route(
            "/v1/content/import",
            post(import)
                .layer(axum::extract::DefaultBodyLimit::max(memoswish_content::deckpack::DOCUMENT_BYTES + 1024)),
        )
        .route("/v1/content/cards/{id}/publication", post(publication))
        .route("/v1/content/cards/{id}/reports", get(reports).post(report))
        .route("/v1/content/cards/{id}/revisions", get(revisions))
        .route("/v1/content/decks/{id}", post(edit_deck))
        .route("/v1/content/starters", get(starters))
        .route("/v1/content/starters/{id}/install", post(install))
        // 复用正文预算，额外只容纳来源元数据与命令包络，不缩小富卡编辑范围。
        .layer(axum::extract::DefaultBodyLimit::max(memoswish_core::imports::IMPORT_CONTENT_BYTES + 16 * 1024 + 2048))
        .layer(axum::middleware::from_fn(no_store))
}
fn body<T: serde::de::DeserializeOwned>(v: Result<Json<serde_json::Value>, JsonRejection>) -> Result<T, CoreError> {
    let Json(value) = v.map_err(|_| CoreError::invalid("invalid content command"))?;
    memoswish_core::imports::decode_input(value, 15 * 1024 * 1024)
}
async fn save(
    State(st): State<AppState>,
    Auth(p): Auth,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<Card>> {
    Ok(Json(st.services.save_card(&p, body(v)?).await?))
}
async fn publication(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(id): Path<String>,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<Card>> {
    Ok(Json(st.services.publish_card(&p, &id, body(v)?).await?))
}
async fn edit_deck(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(id): Path<String>,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<Deck>> {
    Ok(Json(st.services.edit_deck(&p, &id, &body(v)?).await?))
}
async fn report(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(id): Path<String>,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<ContentReport>> {
    Ok(Json(st.services.report_content(&p, &id, &body(v)?).await?))
}
#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    offset: u32,
    #[serde(default = "limit")]
    limit: u32,
    #[serde(default = "before")]
    before: u64,
}
fn limit() -> u32 {
    50
}
fn before() -> u64 {
    u64::from(u32::MAX) + 1
}
fn page(v: Result<Query<Page>, QueryRejection>) -> Result<Page, CoreError> {
    v.map(|Query(p)| p).map_err(|_| CoreError::invalid("invalid content pagination"))
}
async fn reports(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(id): Path<String>,
    q: Result<Query<Page>, QueryRejection>,
) -> ApiResult<Json<Vec<ContentReport>>> {
    let q = page(q)?;
    Ok(Json(st.services.content_reports(&p, &id, q.offset, q.limit).await?))
}
async fn revisions(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(id): Path<String>,
    q: Result<Query<Page>, QueryRejection>,
) -> ApiResult<Json<Vec<CardRevision>>> {
    let q = page(q)?;
    Ok(Json(st.services.content_revisions(&p, &id, q.before, q.limit).await?))
}
async fn starters(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<Json<Vec<StarterDeck>>> {
    Ok(Json(st.services.starter_catalog(&p).await?))
}
async fn install(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<Deck>> {
    let command: StarterInstall = body(v)?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let credential = st.services.auth.import_credential(&p, bearer)?;
    Ok(Json(st.services.install_starter(&p, &id, &command.idempotency_key, Some(credential)).await?))
}
async fn no_store(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}

async fn import(
    State(st): State<AppState>,
    Auth(p): Auth,
    headers: axum::http::HeaderMap,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<Deck>> {
    let input: serde_json::Value = body(v)?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let credential = st.services.auth.import_credential(&p, bearer)?;
    Ok(Json(st.services.import_authored_content_input(&p, input, Some(credential)).await?))
}

async fn create_deck(
    State(st): State<AppState>,
    Auth(p): Auth,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<Deck>> {
    Ok(Json(st.services.create_authored_deck(&p, body(v)?).await?))
}

async fn import_apkg(
    State(st): State<AppState>,
    Auth(p): Auth,
    headers: axum::http::HeaderMap,
    v: Result<Json<serde_json::Value>, JsonRejection>,
) -> ApiResult<Json<memoswish_content::apkg::ApkgReport>> {
    let input: ContentApkgImport = body(v)?;
    let bytes = memoswish_content::apkg::decode_base64_request(&input.apkg.apkg_base64)?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let credential = st.services.auth.import_credential(&p, bearer)?;
    Ok(Json(st.services.import_authored_apkg(&p, bytes, input, Some(credential)).await?))
}
