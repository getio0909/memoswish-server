//! HTTP API（App 客户端使用）。端点由本模块注册。

use axum::body::{Body, Bytes};
use axum::extract::rejection::{BytesRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use memoswish_content::NewDeck;
use memoswish_content::apkg::{ApkgLimits, ApkgOptions};
use memoswish_core::{CoreError, Permission, Principal};
use memoswish_mcp::http::HttpState;
use memoswish_protocol::{ApiError, ExplainRequest, FeedQuery, FeedbackBatch, LoginRequest, RegisterRequest};
use serde::Deserialize;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::app::AppState;

/// 领域错误到 HTTP 响应的映射。
pub struct ApiErr(pub CoreError);

impl From<CoreError> for ApiErr {
    fn from(e: CoreError) -> Self {
        ApiErr(e)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let message = self.0.public_message().to_string();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(target: "memoswish::api", code = self.0.code(), "internal error");
        }
        let mut resp = (status, Json(ApiError { code: self.0.code().into(), message })).into_response();
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer realm=\"learntok\""));
        }
        if matches!(status, StatusCode::SERVICE_UNAVAILABLE | StatusCode::TOO_MANY_REQUESTS) {
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        resp
    }
}

pub(crate) type ApiResult<T> = Result<T, ApiErr>;

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(str::to_string)
}

/// 账户提取器只接受账户根 JWT/opaque，不把委托凭据转换成第一方会话。
pub struct AccountAuth(pub memoswish_core::AccountPrincipal);
impl FromRequestParts<AppState> for AccountAuth {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = bearer(&parts.headers).ok_or_else(|| CoreError::Unauthorized("missing account session".into()))?;
        Ok(Self(state.services.auth.authenticate_account(&token).await?))
    }
}

/// 生命周期账户边界保留最初验证的账户或工作区凭据。
pub struct LifecycleAccountAuth(pub memoswish_core::lifecycle::AccountAuthority);
impl FromRequestParts<AppState> for LifecycleAccountAuth {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(Self(state.services.auth.authenticate_lifecycle_account(bearer(&parts.headers).as_deref()).await?))
    }
}

/// 认证提取器。
pub struct Auth(pub Principal);

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiErr;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = bearer(&parts.headers);
        let principal = state.services.auth.authenticate(token.as_deref()).await?;
        let path = parts.uri.path();
        if !path.starts_with("/v1/privacy/")
            && !path.starts_with("/v1/account")
            && !path.starts_with("/v1/workspace/")
            && path != "/v1/auth/refresh"
        {
            state.services.auth.require_privacy_collection(&principal).await?;
        }
        // 作者入口复用部署的租户准入后端，在正文解码与任何写入前拒绝超额请求。
        if parts.method == axum::http::Method::POST && path.starts_with("/v1/content/") {
            state.services.limiter.check(&principal.tenant_id, 1.0).await?;
        }
        Ok(Auth(principal))
    }
}

/// 构建完整路由。
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .merge(crate::sessions::router())
        .merge(crate::access::router())
        .merge(crate::password_routes::router())
        .merge(crate::privacy::router())
        .merge(crate::diagnostics::router())
        .merge(crate::content_lifecycle::router())
        .merge(crate::learning_controls::router())
        .route("/metrics", get(metrics))
        .merge(crate::admin::router())
        .route("/v1/server-info", get(server_info))
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/refresh", post(refresh_token))
        .route("/v1/auth/account-sessions", post(account_login))
        .route("/v1/auth/account-sessions/refresh", post(account_refresh))
        .route("/v1/auth/account-sessions/workspace", post(account_workspace))
        .route("/v1/account/profile", get(account_profile))
        .route("/v1/account/empty/export", get(account_export_empty))
        .route("/v1/account/empty", delete(account_close_empty))
        .route("/v1/me", get(me))
        .route("/v1/usage", get(usage))
        .route("/v1/account/export/full", get(export_personal_account))
        .route("/v1/workspace/export", get(export_workspace))
        .route("/v1/workspace/leave", post(leave_workspace))
        .route("/v1/workspace/delete", post(delete_workspace))
        .route("/v1/workspace/transfer-ownership", post(transfer_ownership))
        .route("/v1/account/close", post(close_account))
        .route("/v1/account/lifecycle-policy", get(lifecycle_policy))
        .route("/v1/account/export", get(export_account))
        .route("/v1/account", delete(delete_account))
        .route("/v1/feed", get(feed))
        .route("/v1/feedback", post(feedback))
        .route("/v1/stats", get(stats))
        .route("/v1/starred", get(starred))
        .merge(crate::library::routes())
        .route("/v1/decks", get(list_decks).post(create_deck))
        .route("/v1/decks/import", post(import_deck))
        .route(
            "/v1/decks/import/portable",
            post(import_portable).layer(DefaultBodyLimit::max(memoswish_content::deckpack::DOCUMENT_BYTES)),
        )
        .route("/v1/decks/{deck_id}/export/portable", get(export_portable))
        .route("/v1/decks/import/apkg", post(import_apkg).layer(DefaultBodyLimit::max(ApkgLimits::ARCHIVE)))
        .route("/v1/decks/{deck_id}/cards", get(deck_cards))
        .route("/v1/decks/{deck_id}/export", get(export_deck))
        .route("/v1/cards/{card_id}", get(get_card).delete(delete_card))
        .route("/v1/cards/{card_id}/explain", post(explain_card))
        .route("/v1/explanations/{request_id}", get(explanation_operation))
        .route("/v1/explanations/{request_id}/reconcile", post(reconcile_explanation))
        .route("/v1/bgm", get(list_bgm))
        .route("/assets/{*key}", get(asset))
        .route("/v1/{*rest}", delete(not_found).get(not_found).post(not_found))
        .with_state(state.clone());

    let mut app = api
        .layer(middleware::from_fn_with_state(state.clone(), crate::auth_defenses::guard))
        .merge(state.health.router());
    if state.config.mcp.http_enabled {
        let mcp = memoswish_mcp::http::router(HttpState {
            server: state.mcp.clone(),
            #[cfg(feature = "mcp-oauth")]
            oauth: state.oauth.clone(),
            allowed_origins: std::sync::Arc::new(state.config.mcp.allowed_origins.clone()),
            allowed_hosts: std::sync::Arc::new(state.config.mcp.allowed_hosts.clone()),
        })
        // 允许通过 MCP 上传 ≤ 10 MiB 的 BGM（base64 膨胀约 4/3）。
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024));
        app = app.merge(mcp);
    }
    #[cfg(feature = "oidc")]
    if let Some(oidc) = state.oidc.clone() {
        app = app.merge(crate::oidc::router(oidc));
    }
    app = app.layer(cors(&state.config.cors_origins));
    #[cfg(feature = "mcp-oauth")]
    if let Some(oauth) = state.oauth.clone() {
        app = app.merge(
            crate::oauth::router(oauth, cors(&state.config.cors_origins))
                .layer(middleware::from_fn_with_state(state.clone(), crate::auth_defenses::guard)),
        );
    }
    instrument(app, state)
}

pub(crate) fn instrument(app: Router, state: AppState) -> Router {
    app.layer(middleware::from_fn_with_state(state.clone(), count_requests))
        .layer(middleware::from_fn(crate::admin::headers))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<Body>| {
            tracing::info_span!("http_request", route = crate::metrics::route(request))
        }))
}

/// 统计 HTTP 请求总数的中间件。
async fn count_requests(State(st): State<AppState>, req: Request, next: Next) -> Response {
    st.http_requests_total.inc();
    let mut observation = st.metrics.http(crate::metrics::route(&req));
    if matches!(
        st.health.lifecycle.phase(),
        crate::lifecycle::Phase::Draining | crate::lifecycle::Phase::Stopped | crate::lifecycle::Phase::Failed
    ) && !matches!(req.uri().path(), "/healthz" | "/livez" | "/readyz" | "/startupz")
    {
        let response = draining_response(&st, req.uri().path());
        observation.finish(response.status());
        return response;
    }
    let response = next.run(req).await;
    observation.finish(response.status());
    response
}

// 关闭发生在路由适配器前，仍保留各传输的错误封套与安全响应头。
fn draining_response(st: &AppState, path: &str) -> Response {
    let mut response = if path == "/mcp" && st.config.mcp.http_enabled {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(memoswish_mcp::protocol::failure(
                serde_json::Value::Null,
                memoswish_mcp::protocol::codes::INTERNAL_ERROR,
                "server is draining",
            )),
        )
            .into_response()
    } else if cfg!(feature = "mcp-oauth")
        && st.config.oauth.enabled
        && (path.starts_with("/oauth/") || path.starts_with("/.well-known/oauth-"))
    {
        let mut response = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error":"temporarily_unavailable", "error_description":"server is draining"
            })),
        )
            .into_response();
        for (key, value) in [
            (header::PRAGMA, "no-cache"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            ),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ] {
            response.headers_mut().insert(key, HeaderValue::from_static(value));
        }
        response
    } else {
        ApiErr(CoreError::Unavailable("server is draining".into())).into_response()
    };
    response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Prometheus `/metrics` 指标导出。
async fn metrics(State(st): State<AppState>) -> Response {
    st.metrics.response(true)
}

fn cors(origins: &[String]) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            axum::http::HeaderName::from_static("idempotency-key"),
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::RANGE,
            axum::http::HeaderName::from_static("mcp-protocol-version"),
            axum::http::HeaderName::from_static("mcp-session-id"),
        ])
        .expose_headers([
            header::CONTENT_RANGE,
            header::ETAG,
            header::WWW_AUTHENTICATE,
            axum::http::HeaderName::from_static("mcp-session-id"),
            axum::http::HeaderName::from_static("mcp-protocol-version"),
        ]);
    if origins.iter().any(|o| o == "*") {
        base.allow_origin(Any)
    } else {
        let list: Vec<HeaderValue> = origins.iter().filter_map(|o| HeaderValue::from_str(o).ok()).collect();
        base.allow_origin(AllowOrigin::list(list))
    }
}

async fn not_found() -> ApiErr {
    ApiErr(CoreError::NotFound("endpoint".into()))
}

async fn server_info(State(st): State<AppState>) -> impl IntoResponse {
    Json(st.server_info())
}

async fn register(State(st): State<AppState>, Json(req): Json<RegisterRequest>) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.auth.register(&req).await?))
}

async fn login(State(st): State<AppState>, Json(req): Json<LoginRequest>) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.auth.login(&req).await?))
}

/// 刷新当前调用主体的 JWT 访问令牌。
async fn refresh_token(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.auth.refresh(&p).await?))
}

async fn account_login(
    State(st): State<AppState>,
    body: Result<Json<LoginRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(req) = body.map_err(|_| CoreError::invalid("invalid account session request"))?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(st.services.auth.login_account(&req).await?)))
}
async fn account_refresh(State(st): State<AppState>, AccountAuth(p): AccountAuth) -> ApiResult<impl IntoResponse> {
    if p.session_id.is_some() {
        return Err(CoreError::Unauthorized("refresh token required".into()).into());
    }
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(st.services.auth.refresh_account(&p).await?)))
}
async fn account_profile(State(st): State<AppState>, AccountAuth(p): AccountAuth) -> ApiResult<impl IntoResponse> {
    if st.repo.account_generation(&p.user_id).await? != p.generation {
        return Err(CoreError::Unauthorized("account session was revoked".into()).into());
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json({
            let a = st
                .repo
                .account_by_id(&p.user_id)
                .await?
                .ok_or_else(|| CoreError::Unauthorized("account no longer exists".into()))?;
            memoswish_protocol::AccountProfile { user_id: a.id, email: a.email, display_name: a.display_name }
        }),
    ))
}
async fn account_workspace(
    State(st): State<AppState>,
    AccountAuth(p): AccountAuth,
    body: Result<Json<memoswish_protocol::WorkspaceSessionRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(req) = body.map_err(|_| CoreError::invalid("invalid account session request"))?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(st.services.auth.select_workspace(&p, &req.tenant_id).await?)))
}
async fn account_export_empty(State(st): State<AppState>, AccountAuth(p): AccountAuth) -> ApiResult<impl IntoResponse> {
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(st.repo.account_export_empty(&p.user_id, p.generation).await?)))
}
async fn account_close_empty(State(st): State<AppState>, AccountAuth(p): AccountAuth) -> ApiResult<StatusCode> {
    let job = st.repo.account_close_empty(&p.user_id, p.generation).await?;
    Ok(if crate::account::finish(&st, &job).await.is_ok() { StatusCode::NO_CONTENT } else { StatusCode::ACCEPTED })
}

async fn me(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.auth.profile(&p).await?))
}

/// 查询当前租户的配额与月度用量快照。
async fn usage(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.usage(&p).await?))
}

/// 导出完整账户资料和资产，不包含密码、摘要、原始令牌或浏览器绑定。
async fn export_account(State(st): State<AppState>, Auth(p): Auth, headers: HeaderMap) -> ApiResult<impl IntoResponse> {
    let data = crate::account::export(&st, &p).await?;
    st.services.auth.authenticate(bearer(&headers).as_deref()).await?;
    let token_hash = bearer(&headers).map(|t| memoswish_auth::token::hash_api_token(&t));
    st.repo.revalidate_workspace_export(&p, token_hash.as_deref()).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(data)))
}

/// 旧客户端在整个 2.x 保留原子兼容映射，错误同样带弃用提示。
async fn delete_account(State(st): State<AppState>, auth: Result<Auth, ApiErr>) -> Response {
    let result: ApiResult<StatusCode> = async {
        let Auth(p) = auth?;
        let jobs = st.services.legacy_close_account(&p).await?;
        Ok(finish_lifecycle(&st, &jobs).await)
    }
    .await;
    let mut response = result.into_response();
    response.headers_mut().insert("deprecation", HeaderValue::from_static("@1794009600"));
    response.headers_mut().insert(
        header::LINK,
        HeaderValue::from_static("<account/lifecycle-policy>; rel=\"deprecation\"; type=\"text/plain\""),
    );
    response
}

async fn lifecycle_policy() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        concat!(
            env!("BRAND_EN_PRODUCT"),
            " 2.6 lifecycle policy (2026-11-07): DELETE /v1/account is deprecated and remains available throughout 2.x. One non-owner membership closes only the caller account; one owner membership deletes that workspace and closes only the caller account; multiple memberships return use_explicit_command. Use POST /v1/workspace/leave, /v1/workspace/delete or /v1/account/close with explicit confirmations. Retries do not replay responses. After a lost response, inspect state; permit at most one manually initiated retry with the same original credential and confirmations. Stop on 401, 403 or 409. Never retry automatically with a rejoined membership, new credential or new confirmation set. Pending cleanup is durable; 202 does not mean external cleanup completed."
        ),
    )
}

async fn finish_lifecycle(st: &AppState, jobs: &[memoswish_core::identity::ErasureJob]) -> StatusCode {
    let mut pending = false;
    for job in jobs {
        pending |= crate::account::finish(st, job).await.is_err();
    }
    if pending { StatusCode::ACCEPTED } else { StatusCode::NO_CONTENT }
}

async fn export_personal_account(
    State(st): State<AppState>,
    LifecycleAccountAuth(p): LifecycleAccountAuth,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let data = st.services.export_personal(&p).await?;
    // 完整读取结束后重验原 JWT 的期限，最终 SQL 屏障仍使用最初捕获的主体。
    st.services.auth.authenticate_lifecycle_account(bearer(&headers).as_deref()).await?;
    st.repo.revalidate_account_export(&p).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(data)))
}

async fn export_workspace(
    State(st): State<AppState>,
    Auth(p): Auth,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let mut data = st.services.export_workspace(&p).await?;
    crate::account::complete_workspace_export(&st, &p, &mut data).await?;
    st.services.auth.authenticate(bearer(&headers).as_deref()).await?;
    let token_hash = bearer(&headers).map(|t| memoswish_auth::token::hash_api_token(&t));
    st.repo.revalidate_workspace_export(&p, token_hash.as_deref()).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(data)))
}

async fn leave_workspace(
    State(st): State<AppState>,
    Auth(p): Auth,
    body: Result<Json<memoswish_protocol::WorkspaceConfirmation>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<StatusCode> {
    let Json(req) = body.map_err(|_| CoreError::invalid("invalid workspace confirmation"))?;
    if req.confirmed_tenant_id != p.tenant_id {
        return Err(CoreError::invalid("workspace confirmation mismatch").into());
    }
    st.services.leave_workspace(&p).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_workspace(
    State(st): State<AppState>,
    Auth(p): Auth,
    body: Result<Json<memoswish_protocol::WorkspaceConfirmation>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<StatusCode> {
    let Json(req) = body.map_err(|_| CoreError::invalid("invalid workspace confirmation"))?;
    if req.confirmed_tenant_id != p.tenant_id {
        return Err(CoreError::invalid("workspace confirmation mismatch").into());
    }
    let job = st
        .services
        .delete_workspace(
            &p,
            &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: req.confirmed_tenant_id },
        )
        .await?;
    Ok(finish_lifecycle(&st, &[job]).await)
}

async fn transfer_ownership(
    State(st): State<AppState>,
    Auth(p): Auth,
    body: Result<Json<memoswish_protocol::TransferOwnershipRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<StatusCode> {
    let Json(req) = body.map_err(|_| CoreError::invalid("invalid ownership transfer"))?;
    st.services
        .transfer_ownership(
            &p,
            &memoswish_core::lifecycle::TransferOwnership { successor_user_id: req.successor_user_id },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn close_account(
    State(st): State<AppState>,
    LifecycleAccountAuth(p): LifecycleAccountAuth,
    body: Result<Json<memoswish_protocol::CloseAccountRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<StatusCode> {
    let Json(req) = body.map_err(|_| CoreError::invalid("invalid account confirmation"))?;
    if req.confirmed_user_id != p.user_id() {
        return Err(CoreError::invalid("account confirmation mismatch").into());
    }
    let jobs = st
        .services
        .close_account_authorized(
            &p,
            &memoswish_core::lifecycle::CloseAccount {
                confirmed_exclusive_workspaces: req.confirmed_exclusive_workspaces,
            },
        )
        .await?;
    Ok(finish_lifecycle(&st, &jobs).await)
}

async fn feed(State(st): State<AppState>, Auth(p): Auth, Query(q): Query<FeedQuery>) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.next_page(&p, &q).await?))
}

async fn feedback(
    State(st): State<AppState>,
    Auth(p): Auth,
    Json(b): Json<FeedbackBatch>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.record_feedback(&p, &b).await?))
}

#[derive(Deserialize, Default)]
struct DeckFilter {
    deck_id: Option<String>,
}

async fn stats(State(st): State<AppState>, Auth(p): Auth, Query(f): Query<DeckFilter>) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.stats_for_deck(&p, f.deck_id.as_deref()).await?))
}

async fn starred(
    State(st): State<AppState>,
    Auth(p): Auth,
    Query(f): Query<DeckFilter>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.list_starred_cards(&p, f.deck_id.as_deref()).await?))
}

async fn list_decks(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.list_decks(&p).await?))
}

async fn create_deck(
    State(st): State<AppState>,
    Auth(p): Auth,
    Json(d): Json<serde_json::Value>,
) -> ApiResult<impl IntoResponse> {
    let d: NewDeck = memoswish_core::imports::decode_input(d, 15 * 1024 * 1024)?;
    Ok((StatusCode::CREATED, Json(st.services.create_deck(&p, d).await?)))
}

#[derive(Deserialize)]
struct Page {
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn deck_cards(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(deck_id): Path<String>,
    Query(pg): Query<Page>,
) -> ApiResult<impl IntoResponse> {
    st.services.get_deck(&p, &deck_id).await?;
    Ok(Json(st.services.list_cards(&p, Some(&deck_id), pg.limit.unwrap_or(200), pg.offset.unwrap_or(0)).await?))
}

async fn get_card(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(card_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.get_card(&p, &card_id).await?))
}

async fn delete_card(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(card_id): Path<String>,
    query: Result<Query<memoswish_protocol::RevisionPrecondition>, QueryRejection>,
) -> ApiResult<StatusCode> {
    let Query(condition) = query.map_err(|e| CoreError::invalid(e.body_text()))?;
    st.services.delete_card_if_revision(&p, &card_id, condition.expected_revision).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn explain_card(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(card_id): Path<String>,
    body: Result<Json<ExplainRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(req) = body.map_err(|_| memoswish_core::CoreError::invalid("invalid explanation request body"))?;
    Ok(Json(st.services.explain_card(&p, &card_id, &req).await?))
}

async fn export_deck(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(deck_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.export_deck(&p, &deck_id).await?))
}

fn import_identity(
    auth: &memoswish_auth::AuthService,
    p: &Principal,
    headers: &HeaderMap,
) -> Result<(Option<String>, Option<memoswish_core::imports::ImportCredential>), CoreError> {
    let keys: Vec<_> = headers.get_all("idempotency-key").iter().collect();
    if keys.len() > 1 {
        return Err(CoreError::invalid("duplicate Idempotency-Key"));
    }
    let key = keys
        .first()
        .map(|h| h.to_str().map(str::to_owned).map_err(|_| CoreError::invalid("invalid Idempotency-Key")))
        .transpose()?;
    if let Some(key) = &key {
        memoswish_core::imports::validate_request_id(key)?;
    }
    let hash = Some(auth.import_credential(
        p,
        headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")),
    )?);
    Ok((key, hash))
}

async fn import_apkg(
    State(st): State<AppState>,
    Auth(p): Auth,
    headers: HeaderMap,
    query: Result<Query<ApkgOptions>, QueryRejection>,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult<impl IntoResponse> {
    p.require(Permission::ContentWrite)?;
    st.services.limiter.check(&p.tenant_id, 1.0).await?;
    let Query(options) = query.map_err(|e| CoreError::invalid(format!("invalid APKG options: {e}")))?;
    let bytes = body.map_err(|_| CoreError::invalid("APKG body is unreadable or exceeds 10 MiB"))?;
    let (key, hash) = import_identity(&st.services.auth, &p, &headers)?;
    let report = st.services.import_apkg_with_identity(&p, bytes.to_vec(), options, key, hash).await?;
    Ok((StatusCode::CREATED, Json(report)))
}

async fn import_deck(
    State(st): State<AppState>,
    Auth(p): Auth,
    headers: HeaderMap,
    Json(pack): Json<serde_json::Value>,
) -> ApiResult<impl IntoResponse> {
    let (key, hash) = import_identity(&st.services.auth, &p, &headers)?;
    let deck = st.services.import_deck_pack_input(&p, pack, false, key, hash).await?;
    Ok((StatusCode::CREATED, Json(deck)))
}

async fn list_bgm(State(st): State<AppState>, Auth(p): Auth) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.services.list_bgm(&p).await?))
}

#[derive(Deserialize)]
struct AssetQuery {
    /// 只在 deprecated bridge 接受历史 query token。
    access_token: Option<String>,
    delivery: Option<u8>,
    surface: Option<String>,
    owner: Option<String>,
}

/// 解析单段 `Range: bytes=a-b`。
fn parse_range(h: &str, len: u64) -> Option<(u64, u64)> {
    if len == 0 || h.len() > 128 || h.contains(',') {
        return None;
    }
    let ranges = http_range_header::parse_range_header(h).ok()?.validate(len).ok()?;
    let range = ranges.first()?;
    (ranges.len() == 1).then_some((*range.start(), *range.end()))
}

/// 资产下载：支持 ETag / 304 与单段 Range（iOS AVPlayer 播放音频必需）。
async fn asset(
    State(st): State<AppState>,
    Path(key): Path<String>,
    query: Result<Query<AssetQuery>, QueryRejection>,
    headers: HeaderMap,
    method: Method,
) -> ApiResult<Response> {
    use memoswish_application::asset_delivery;
    let Query(q) = query.map_err(|_| CoreError::invalid("invalid asset delivery query"))?;
    memoswish_core::store::validate_key(&key)?;
    let public = asset_delivery::is_builtin(&key);
    if q.delivery.is_some_and(|value| value != 1) || (q.delivery.is_some() && q.access_token.is_some()) {
        return Err(ApiErr(CoreError::invalid("query tokens are only accepted by the legacy asset bridge")));
    }
    let token = bearer(&headers).or(q.access_token);
    let p = if public {
        memoswish_core::Principal::local_owner("public_asset")
    } else {
        let principal = st.services.auth.authenticate(token.as_deref()).await?;
        st.services.auth.require_privacy_collection(&principal).await?;
        principal
    };
    let surface = q.surface.as_deref().unwrap_or_else(|| {
        if p.can(memoswish_core::Permission::MediaRead) {
            "media"
        } else if p.can(memoswish_core::Permission::ContentRead) {
            "content"
        } else {
            "feed"
        }
    });
    if q.delivery.is_some() && !public && surface != "media" && q.owner.is_none() {
        return Err(ApiErr(CoreError::invalid("asset attachment owner is required")));
    }
    let mut selected_surface = surface;
    let mut result =
        asset_delivery::open(st.repo.as_ref(), st.store.as_ref(), &p, &key, surface, q.owner.as_deref()).await;
    if result.is_err() && q.delivery.is_none() && !key.starts_with(&format!("{}uploads/", p.asset_prefix())) {
        for candidate in ["content", "feed", "media"] {
            if p.can(asset_delivery::permission(candidate)?) {
                result = asset_delivery::open(st.repo.as_ref(), st.store.as_ref(), &p, &key, candidate, None).await;
                if result.is_ok() {
                    selected_surface = candidate;
                    break;
                }
            }
        }
    }
    let delivery = result?;
    let deadline = delivery.deadline();
    let selected = delivery.selected.clone();
    let trusted = delivery.manifest.is_some();
    let cache = if public { "public, max-age=86400" } else { "private, no-cache" };
    let etag = format!("\"{}\"", selected.spec.sha256);
    let len = selected.spec.size as u64;
    // 未验证的历史引用即使本轮完整读取成功，也不获得元数据条件成功。
    let not_modified = trusted && if_none_match(&headers, &etag);
    let range = if method == Method::HEAD || not_modified || !if_range(&headers, &etag) {
        None
    } else {
        headers.get(header::RANGE).and_then(|v| v.to_str().ok())
    };
    let selected_range = range.map(|range| parse_range(range, len));
    let status = if not_modified {
        StatusCode::NOT_MODIFIED
    } else if selected_range == Some(None) {
        StatusCode::RANGE_NOT_SATISFIABLE
    } else if selected_range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let (start, end) = selected_range.flatten().unwrap_or((0, len.saturating_sub(1)));
    let body = if method == Method::HEAD || len == 0 || not_modified || status == StatusCode::RANGE_NOT_SATISFIABLE {
        Body::empty()
    } else {
        Body::from_stream(delivery.body(start, end).await?)
    };
    tokio::time::timeout_at(deadline, async {
        if !public {
            // 首块及元数据 IO 之后重验原凭据域与精确选定投影，不能只检查任意 publication 存在。
            let current = st.services.auth.authenticate(token.as_deref()).await?;
            st.services.auth.require_privacy_collection(&current).await?;
            let current_selection = asset_delivery::select(
                st.repo.as_ref(),
                st.store.as_ref(),
                &current,
                &key,
                selected_surface,
                q.owner.as_deref(),
            )
            .await?;
            if current_selection != selected {
                return Err(ApiErr(CoreError::Conflict("asset selection changed before response".into())));
            }
        }
        Ok::<(), ApiErr>(())
    })
    .await
    .map_err(|_| ApiErr(CoreError::Unavailable("asset admission deadline exceeded".into())))??;
    let mut response = Response::builder()
        .status(status)
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, cache)
        .header(header::ACCEPT_RANGES, "bytes");
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        response = response.header(header::CONTENT_RANGE, format!("bytes */{len}"));
    } else if !not_modified {
        response = response.header(header::CONTENT_TYPE, &selected.spec.mime);
        if status == StatusCode::PARTIAL_CONTENT {
            response = response
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, end - start + 1);
        } else {
            response = response.header(header::CONTENT_LENGTH, len);
        }
    }
    response.body(body).map_err(|e| ApiErr(CoreError::internal(e)))
}

fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers.get_all(header::IF_NONE_MATCH).iter().filter_map(|value| value.to_str().ok()).any(|value| {
        value.split(',').any(|tag| {
            let tag = tag.trim();
            tag == "*" || tag.strip_prefix("W/").unwrap_or(tag) == etag
        })
    })
}

fn if_range(headers: &HeaderMap, etag: &str) -> bool {
    headers.get(header::IF_RANGE).is_none_or(|value| value.to_str().ok() == Some(etag))
}

async fn export_portable(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let credential = Some(st.services.auth.import_credential(
        &p,
        headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")),
    )?);
    Ok(Json(st.services.export_portable_deck(&p, &id, credential).await?))
}
async fn import_portable(
    State(st): State<AppState>,
    Auth(p): Auth,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<impl IntoResponse> {
    let Json(pack) = body.map_err(|_| CoreError::invalid("invalid portable DeckPack request"))?;
    let (key, credential) = import_identity(&st.services.auth, &p, &headers)?;
    Ok((StatusCode::CREATED, Json(st.services.import_portable_deck_input(&p, pack, key, credential).await?)))
}

async fn explanation_operation(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(request_id): Path<String>,
) -> ApiResult<Json<memoswish_protocol::ExplainOperation>> {
    Ok(Json(st.services.explanation_operation(&p, &request_id).await?))
}

async fn reconcile_explanation(
    State(st): State<AppState>,
    Auth(p): Auth,
    Path(request_id): Path<String>,
    body: Result<Json<memoswish_protocol::ExplainReconcileRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<memoswish_protocol::ExplainOperation>> {
    let Json(request) = body.map_err(|_| memoswish_core::CoreError::invalid("invalid explanation evidence body"))?;
    Ok(Json(st.services.reconcile_explanation_request(&p, &request_id, &request).await?))
}

#[cfg(test)]
mod tests {
    use super::parse_range;

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_range("bytes=900-", 1000), Some((900, 999)));
        assert_eq!(parse_range("bytes=-100", 1000), Some((900, 999)));
        assert_eq!(parse_range("bytes=0-5000", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=1000-", 1000), None);
        assert_eq!(parse_range("bytes=0-1,5-6", 1000), None);
        assert_eq!(parse_range("items=0-1", 1000), None);
    }
}
