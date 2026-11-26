//! 固定配置主机、DNS 地址检查和连接地址钉住防止 SSRF 与 DNS 重绑定。
use crate::oidc_config::OidcProvider;
use memoswish_core::{CoreError, CoreResult};
use serde::de::DeserializeOwned;
use std::{net::IpAddr, time::Duration};

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0)
                && !v.is_broadcast()
                && !v.is_documentation()
                && !(a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(v) => {
            // 保守只接受全球单播，排除文档、映射 IPv4 与本地范围。
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && (s[1] == 0xdb8 || s[1] < 0x200))
        }
    }
}

pub async fn client(p: &OidcProvider, endpoint: &str) -> CoreResult<reqwest::Client> {
    let u = p.validate_url(endpoint)?;
    let host = u.host_str().ok_or_else(|| CoreError::invalid("OIDC endpoint has no host"))?;
    let addrs = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host, u.port_or_known_default().unwrap_or(443))),
    )
    .await
    .map_err(|_| CoreError::internal("OIDC DNS timeout"))?
    .map_err(|_| CoreError::internal("OIDC DNS resolution failed"))?
    .collect::<Vec<_>>();
    if addrs.is_empty() || (!p.allow_private_network && addrs.iter().any(|a| !public_ip(a.ip()))) {
        return Err(CoreError::invalid("OIDC endpoint resolved to a prohibited address"));
    }
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|_| CoreError::internal("OIDC HTTP client initialization failed"))
}

pub async fn json<T: DeserializeOwned>(mut response: reqwest::Response) -> CoreResult<(T, u64)> {
    if !response.status().is_success() {
        return Err(CoreError::Unauthorized("OIDC upstream request failed".into()));
    }
    const CAP: usize = 256 * 1024;
    if response.content_length().is_some_and(|n| n > CAP as u64) {
        return Err(CoreError::invalid("OIDC response exceeds size limit"));
    }
    let mut ttl = response
        .headers()
        .get("cache-control")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.split(',').find_map(|part| {
                part.trim().strip_prefix("max-age=").and_then(|n| n.trim_matches('"').parse::<u64>().ok())
            })
        })
        .unwrap_or(300)
        .min(3600);
    let cache = response.headers().get("cache-control").and_then(|h| h.to_str().ok()).unwrap_or("");
    if cache.split(',').any(|p| ["no-store", "no-cache"].contains(&p.trim())) {
        ttl = 0;
    }
    let age =
        response.headers().get("age").and_then(|h| h.to_str().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    ttl = ttl.saturating_sub(age);
    let mut bytes = Vec::new();
    while let Some(c) = response.chunk().await.map_err(|_| CoreError::internal("OIDC response read failed"))? {
        if bytes.len() + c.len() > CAP {
            return Err(CoreError::invalid("OIDC response exceeds size limit"));
        }
        bytes.extend_from_slice(&c);
    }
    Ok((serde_json::from_slice(&bytes).map_err(|_| CoreError::invalid("invalid OIDC JSON response"))?, ttl))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_nonpublic_addresses() {
        assert!(!public_ip([10, 0, 0, 1].into()));
        assert!(!public_ip(std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).into()));
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.19.1.1",
            "::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()));
        }
    }
}
