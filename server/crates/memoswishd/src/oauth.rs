//! OAuth HTTP 边界：标准错误、受限输入和第一方登录/同意表单。
use axum::extract::{Request, rejection::BytesRejection};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use memoswish_auth::oauth::{OAuthService, Registration, SCOPES, digest, equal};
use memoswish_core::{
    CoreError, Principal,
    oauth::{AuthorizationRequest, OAuthClient},
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tower_http::cors::CorsLayer;
use url::Url;

/// 参考条件：feature mcp-oauth，mode = multi_tenant，oauth.enabled = true，mcp.http_enabled = true。
pub fn router(st: Arc<OAuthService>, cors: CorsLayer) -> Router {
    let endpoints = Router::new()
        .route("/.well-known/oauth-protected-resource", get(resource_metadata))
        .route("/.well-known/oauth-protected-resource/mcp", get(resource_metadata))
        .route("/.well-known/oauth-authorization-server", get(server_metadata))
        .route("/oauth/register", post(register))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke));
    let browser =
        Router::new().route("/oauth/authorize", get(authorize).post(consent)).route("/oauth/login", post(login));
    let protect = |routes: Router<Arc<OAuthService>>| {
        routes
            .method_not_allowed_fallback(|| async {
                error(StatusCode::METHOD_NOT_ALLOWED, "invalid_request", "unsupported HTTP method")
            })
            .layer(DefaultBodyLimit::max(16 * 1024))
            .layer(middleware::from_fn_with_state(st.clone(), guard))
            .with_state(st.clone())
    };
    // CORS 包裹机器端点的全部响应，浏览器交互端点及其预检不启用 CORS。
    protect(endpoints).layer(cors).merge(protect(browser))
}
async fn guard(State(st): State<Arc<OAuthService>>, req: Request, next: Next) -> Response {
    // 固定路由键与独立命名空间共同限制匿名请求。
    let key = match req.uri().path() {
        "/oauth/register" => "register",
        "/oauth/login" => "login",
        "/oauth/token" | "/oauth/revoke" => "token",
        "/oauth/authorize" => "authorize",
        _ => "metadata",
    };
    let decision = if key == "login" { Ok(()) } else { st.limiter.check(key, 1.0).await };
    let mut r = match decision {
        Ok(()) => next.run(req).await,
        Err(CoreError::QuotaExceeded(_)) => {
            error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable", "rate limit exceeded")
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable", "rate limiter unavailable"),
    };
    for (k, v) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ] {
        r.headers_mut().insert(k, v.parse().expect("static header"));
    }
    r
}
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    (status, Json(json!({"error":code,"error_description":description}))).into_response()
}
fn domain(e: CoreError, fallback: &str) -> Response {
    match e {
        CoreError::Invalid(ref s) => error(
            StatusCode::BAD_REQUEST,
            if [
                "invalid_request",
                "invalid_target",
                "invalid_scope",
                "unauthorized_client",
                "unsupported_grant_type",
                "unsupported_response_type",
                "invalid_redirect_uri",
                "invalid_client_metadata",
            ]
            .contains(&s.as_str())
            {
                s
            } else {
                fallback
            },
            "invalid OAuth request",
        ),
        CoreError::Internal(_) => {
            tracing::error!(target: "memoswish::oauth", "OAuth persistence operation failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal server error")
        }
        CoreError::QuotaExceeded(_) => {
            error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable", "capacity reached")
        }
        _ => error(StatusCode::BAD_REQUEST, fallback, "invalid OAuth credential, request or binding"),
    }
}
struct OAuthErr {
    status: StatusCode,
    code: &'static str,
    description: &'static str,
}
impl IntoResponse for OAuthErr {
    fn into_response(self) -> Response {
        let mut response = error(self.status, self.code, self.description);
        if self.code == "invalid_client" {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Basic realm=\"oauth\"".parse().expect("static header"));
        }
        response
    }
}
fn reject(status: StatusCode, code: &'static str, description: &'static str) -> OAuthErr {
    OAuthErr { status, code, description }
}
fn parse(s: &str) -> Result<HashMap<String, String>, OAuthErr> {
    if s.len() > 16384 {
        return Err(reject(StatusCode::BAD_REQUEST, "invalid_request", "request too large"));
    }
    let mut p = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(s.as_bytes()) {
        if p.insert(k.to_string(), v.to_string()).is_some() {
            return Err(reject(
                StatusCode::BAD_REQUEST,
                if k == "resource" { "invalid_target" } else { "invalid_request" },
                "duplicate parameter",
            ));
        }
    }
    Ok(p)
}
fn form(headers: &HeaderMap, body: Result<Bytes, BytesRejection>) -> Result<HashMap<String, String>, OAuthErr> {
    if headers.get(header::CONTENT_TYPE).and_then(|x| x.to_str().ok()).map(|s| s.split(';').next())
        != Some(Some("application/x-www-form-urlencoded"))
    {
        return Err(reject(StatusCode::BAD_REQUEST, "invalid_request", "form encoding required"));
    }
    let bytes = body.map_err(|_| reject(StatusCode::BAD_REQUEST, "invalid_request", "invalid request body"))?;
    parse(std::str::from_utf8(&bytes).map_err(|_| reject(StatusCode::BAD_REQUEST, "invalid_request", "invalid UTF-8"))?)
}
async fn resource_metadata(State(st): State<Arc<OAuthService>>) -> Json<serde_json::Value> {
    Json(
        json!({"resource":st.config.mcp_resource,"authorization_servers":[st.config.issuer],"scopes_supported":SCOPES,"bearer_methods_supported":["header"]}),
    )
}
async fn server_metadata(State(st): State<Arc<OAuthService>>) -> Json<serde_json::Value> {
    let mut v = json!({
        "issuer": st.config.issuer,
        "authorization_endpoint": st.config.endpoint("oauth/authorize"),
        "token_endpoint": st.config.endpoint("oauth/token"),
        "revocation_endpoint": st.config.endpoint("oauth/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": SCOPES,
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": false
    });
    if st.config.dynamic_registration {
        v["registration_endpoint"] = json!(st.config.endpoint("oauth/register"));
    }
    Json(v)
}
async fn register(
    State(st): State<Arc<OAuthService>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if !st.config.dynamic_registration {
        return error(StatusCode::FORBIDDEN, "access_denied", "registration disabled");
    }
    if headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.split(';').next())
        != Some(Some("application/json"))
    {
        return error(StatusCode::BAD_REQUEST, "invalid_client_metadata", "JSON required");
    }
    let Ok(body) = body else {
        return error(StatusCode::BAD_REQUEST, "invalid_client_metadata", "invalid body");
    };
    let r = match serde_json::from_slice::<Registration>(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_client_metadata", "invalid metadata"),
    };
    match st.register(r).await {
        Ok((c, secret)) => {
            let mut v = json!({"client_id":c.id,"client_name":c.name,"redirect_uris":c.redirect_uris,"grant_types":c.grant_types,"response_types":["code"],"token_endpoint_auth_method":c.auth_method,"scope":c.scopes.join(" "),"client_id_issued_at":c.created_at});
            if let Some(s) = secret {
                v["client_secret"] = json!(s);
                v["client_secret_expires_at"] = json!(c.expires_at);
            }
            (StatusCode::CREATED, Json(v)).into_response()
        }
        Err(e) => domain(e, "invalid_client_metadata"),
    }
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
fn cookie(headers: &HeaderMap) -> &str {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').find_map(|p| p.trim().strip_prefix("__Host-lto_browser=")))
        .unwrap_or("")
}
fn page(r: &AuthorizationRequest, csrf: &str, c: &OAuthClient, p: Option<&Principal>, display_name: &str) -> Response {
    let product = escape(env!("BRAND_ZH_PRODUCT"));
    let hidden = format!(
        "<input type=\"hidden\" name=\"request_id\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        escape(&r.id),
        escape(csrf)
    );
    let hostname = Url::parse(&r.redirect_uri).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let details = format!(
        "<p>客户端：{}（{}）</p><p>回调主机：{}</p><p>资源：{}</p><p>权限：{}</p>",
        escape(&c.name),
        escape(&c.id),
        escape(&hostname),
        escape(&r.resource),
        escape(&r.scopes.join(" "))
    );
    let body = match p {
        None => format!(
            "<h1>登录{product}以授权</h1>{details}<form method=\"post\" action=\"/oauth/login\">{hidden}<label>邮箱<input name=\"email\" type=\"email\" required maxlength=\"254\" autocomplete=\"username\"></label><label>密码<input name=\"password\" type=\"password\" required maxlength=\"1024\" autocomplete=\"current-password\"></label><button>登录</button></form>"
        ),
        Some(p) => format!(
            "<h1>授权客户端</h1><p>账户：{}（{}）</p><p>租户：{}</p>{details}<form method=\"post\" action=\"/oauth/authorize\">{hidden}<button name=\"decision\" value=\"approve\">允许</button><button name=\"decision\" value=\"deny\">拒绝</button></form>",
            escape(display_name),
            escape(&p.user_id),
            escape(&p.tenant_id)
        ),
    };
    Html(format!(
        "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>{product}授权</title><body>{body}</body></html>"
    ))
    .into_response()
}
fn set_cookie(mut r: Response, value: &str) -> Response {
    r.headers_mut().insert(
        header::SET_COOKIE,
        format!("__Host-lto_browser={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")
            .parse()
            .expect("generated cookie"),
    );
    r
}
async fn authorize(State(st): State<Arc<OAuthService>>, RawQuery(query): RawQuery) -> Response {
    let p = match parse(query.as_deref().unwrap_or("")) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match st.begin(&p).await {
        Ok((r, cookie, csrf)) => match st.client(&r.client_id).await {
            Ok(c) => set_cookie(page(&r, &csrf, &c, None, ""), &cookie),
            Err(e) => domain(e, "invalid_request"),
        },
        Err(e) => {
            if st.authorization_client(&p).await.is_err() {
                return domain(e, "invalid_request");
            }
            let code = match &e {
                CoreError::Invalid(s) => s.as_str(),
                CoreError::Internal(_) => {
                    tracing::error!(target: "memoswish::oauth", "OAuth persistence operation failed");
                    "server_error"
                }
                CoreError::QuotaExceeded(_) => "temporarily_unavailable",
                _ => "access_denied",
            };
            authorization_redirect(&st, &p["redirect_uri"], p.get("state").map(String::as_str), "error", code)
        }
    }
}
fn authorization_redirect(st: &OAuthService, redirect: &str, state: Option<&str>, key: &str, value: &str) -> Response {
    let Ok(mut u) = Url::parse(redirect) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "invalid redirect");
    };
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("iss", &st.config.issuer);
        if let Some(state) = state {
            q.append_pair("state", state);
        }
        q.append_pair(key, value);
    }
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(header::LOCATION, u.as_str().parse().expect("validated redirect"));
    response
}
async fn login(
    State(st): State<Arc<OAuthService>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let p = match form(&headers, body) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let get = |k: &str| p.get(k).map(String::as_str).unwrap_or("");
    match st.login(get("request_id"), cookie(&headers), get("csrf"), get("email"), get("password")).await {
        Ok((r, cookie, user)) => match (st.client(&r.client_id).await, st.auth.profile(&user).await) {
            (Ok(c), Ok(profile)) => set_cookie(page(&r, get("csrf"), &c, Some(&user), &profile.display_name), &cookie),
            _ => error(StatusCode::BAD_REQUEST, "access_denied", "account unavailable"),
        },
        Err(e) => domain(e, "access_denied"),
    }
}
async fn consent(
    State(st): State<Arc<OAuthService>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let p = match form(&headers, body) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let get = |k: &str| p.get(k).map(String::as_str).unwrap_or("");
    if !["approve", "deny"].contains(&get("decision")) {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "explicit decision required");
    }
    match st.consent(get("request_id"), cookie(&headers), get("csrf"), get("decision") == "approve").await {
        Ok((r, code)) => match code {
            Some(code) => authorization_redirect(&st, &r.redirect_uri, r.state.as_deref(), "code", &code),
            None => authorization_redirect(&st, &r.redirect_uri, r.state.as_deref(), "error", "access_denied"),
        },
        Err(e) => domain(e, "access_denied"),
    }
}
async fn client(st: &OAuthService, headers: &HeaderMap, p: &HashMap<String, String>) -> Result<OAuthClient, OAuthErr> {
    let unauthorized = || reject(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
    let (id, secret, method) = if let Some(h) = headers.get(header::AUTHORIZATION) {
        if p.contains_key("client_secret") {
            return Err(reject(StatusCode::BAD_REQUEST, "invalid_request", "multiple client authentication methods"));
        }
        let b = h
            .to_str()
            .ok()
            .and_then(|s| {
                s.split_once(' ').filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic")).map(|(_, value)| value)
            })
            .and_then(|s| STANDARD.decode(s).ok())
            .and_then(|s| String::from_utf8(s).ok())
            .ok_or_else(unauthorized)?;
        let (id, pw) = b.split_once(':').ok_or_else(unauthorized)?;
        let decode = |s: &str| {
            let encoded = format!("v={s}");
            let mut pairs = url::form_urlencoded::parse(encoded.as_bytes());
            let value = pairs.next().map(|(_, v)| v.into_owned());
            if pairs.next().is_some() { None } else { value }
        };
        let id = decode(id).ok_or_else(unauthorized)?;
        if p.get("client_id").is_some_and(|s| s != &id) {
            return Err(unauthorized());
        }
        (id, Some(decode(pw).ok_or_else(unauthorized)?), "client_secret_basic")
    } else {
        let secret = p.get("client_secret").cloned();
        let method = if secret.is_some() { "client_secret_post" } else { "none" };
        (p.get("client_id").cloned().ok_or_else(unauthorized)?, secret, method)
    };
    let c = st.client(&id).await.map_err(|_| unauthorized())?;
    if c.auth_method != method {
        return Err(unauthorized());
    }
    let ok = match method {
        "none" => secret.is_none(),
        "client_secret_basic" | "client_secret_post" => {
            secret.as_deref().zip(c.secret_hash.as_deref()).is_some_and(|(s, h)| equal(&digest(s), h))
        }
        _ => false,
    };
    if !ok {
        return Err(unauthorized());
    }
    Ok(c)
}
async fn token(
    State(st): State<Arc<OAuthService>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let p = match form(&headers, body) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let c = match client(&st, &headers, &p).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match st.exchange(&c, &p).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => domain(e, "invalid_grant"),
    }
}
async fn revoke(
    State(st): State<Arc<OAuthService>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let p = match form(&headers, body) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let c = match client(&st, &headers, &p).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let Some(raw) = p.get("token") else {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "token required");
    };
    match st.repo.oauth_token(&digest(raw)).await {
        Ok(Some(t)) if t.grant.client_id == c.id => match st.repo.oauth_revoke(&t.grant.tenant_id, &t.grant.id).await {
            Ok(()) => StatusCode::OK.into_response(),
            Err(e) => domain(e, "invalid_request"),
        },
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => domain(e, "invalid_request"),
    }
}
