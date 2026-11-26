//! 管理台静态资源与覆盖成功、拒绝和未知资源的强制浏览器策略。
use crate::app::AppState;
use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, header},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::get,
};
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(|| async { Html(include_str!(concat!(env!("OUT_DIR"), "/admin.html"))) }))
        .route(
            "/admin/script.js",
            get(|| async { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], include_str!("admin.js")) }),
        )
        .route(
            "/admin/style.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("admin.css")) }),
        )
        .route("/admin/{*rest}", get(|| async { axum::http::StatusCode::NOT_FOUND }))
}
pub(crate) fn secure_headers(response: &mut Response, admin: bool) {
    for (key, value) in [
        (
            header::CONTENT_SECURITY_POLICY,
            if admin { CSP } else { "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" },
        ),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
    ] {
        response.headers_mut().insert(key, HeaderValue::from_static(value));
    }
    if response.status() == axum::http::StatusCode::TOO_MANY_REQUESTS
        || response.status() == axum::http::StatusCode::SERVICE_UNAVAILABLE
    {
        response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
}
pub(crate) async fn headers(request: Request, next: Next) -> Response {
    let admin = request.uri().path() == "/admin" || request.uri().path().starts_with("/admin/");
    let mut response = next.run(request).await.into_response();
    if admin {
        secure_headers(&mut response, true);
    }
    response
}
