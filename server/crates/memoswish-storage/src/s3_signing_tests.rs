//! 独立测试端实现 AWS 验签，不调用 rusty-s3；生产代码不保留第二套签名算法。
use super::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn hmac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(bytes);
    mac.finalize().into_bytes().to_vec()
}

pub(super) fn verify(method: &str, target: &str, headers: &HashMap<String, String>, body: &[u8], now: i64) -> bool {
    let Ok(url) = reqwest::Url::parse(&format!("http://localhost{target}")) else { return false };
    let mut query: Vec<_> = url.query_pairs().into_owned().collect();
    let params: HashMap<_, _> = query.iter().cloned().collect();
    let Some(signature) = params.get("X-Amz-Signature") else { return false };
    let Some(credential) = params.get("X-Amz-Credential") else { return false };
    let fields: Vec<_> = credential.split('/').collect();
    if fields.len() != 5 || fields[0] != "AKIAIOSFODNN7EXAMPLE" || fields[3..] != ["s3", "aws4_request"] {
        return false;
    }
    let Some(date) = params.get("X-Amz-Date") else { return false };
    let Ok(date) = chrono::NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ") else { return false };
    let expires = params.get("X-Amz-Expires").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    if !(1..=604800).contains(&expires)
        || now < date.and_utc().timestamp()
        || now > date.and_utc().timestamp() + expires
    {
        return false;
    }
    let Some(signed_headers) = params.get("X-Amz-SignedHeaders") else { return false };
    if method == "PUT" && !signed_headers.split(';').any(|h| h == "x-amz-checksum-sha256") {
        return false;
    }
    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let Some(value) = headers.get(name) else { return false };
        canonical_headers.push_str(&format!("{name}:{}\n", value.split_whitespace().collect::<Vec<_>>().join(" ")));
    }
    if let Some(hash) = headers.get("x-amz-checksum-sha256")
        && hash != &base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
    {
        return false;
    }
    query.retain(|(k, _)| k != "X-Amz-Signature");
    let mut encoded: Vec<_> = query.iter().map(|(k, v)| (uri_encode(k, true), uri_encode(v, true))).collect();
    encoded.sort();
    let canonical_query = encoded.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let request =
        format!("{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD", url.path());
    let scope = fields[1..].join("/");
    let signing = format!("AWS4-HMAC-SHA256\n{}\n{scope}\n{}", params["X-Amz-Date"], sha256_hex(request.as_bytes()));
    let key = hmac(format!("AWS4{SECRET}").as_bytes(), fields[1].as_bytes());
    let key = hmac(&key, fields[2].as_bytes());
    let key = hmac(&key, b"s3");
    let key = hmac(&key, b"aws4_request");
    hex::encode(hmac(&key, signing.as_bytes())) == *signature
}

fn store() -> S3Store {
    S3Store::from_config(S3Config {
        endpoint: "https://s3.example.com:9443/storage/prefix".into(),
        access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
        secret_access_key: SECRET.into(),
        ..Default::default()
    })
}

#[test]
fn aws_published_vector_and_adapter_adversarial_cases() {
    // AWS S3 SigV4 查询签名的公开示例，固定摘要独立于本项目和 rusty-s3。
    let vector = "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
    assert!(verify(
        "GET",
        vector,
        &HashMap::from([("host".into(), "examplebucket.s3.amazonaws.com".into())]),
        &[],
        1369353600
    ));
    let store = store();
    let time = DateTime::from_timestamp(1369353600, 0).unwrap();
    for key in ["tenants/t1/a.wav", "tenants/t1/a_b", "tenants/t1/a-b", "tenants/t1/a.b"] {
        let signed = store.presign_get_url_at(key, 60, time);
        assert_eq!(signed, store.presign_get_url_at(key, 60, time));
        let url = reqwest::Url::parse(&signed).unwrap();
        assert_eq!(url.host_str(), Some("s3.example.com"));
        assert!(url.path().starts_with("/storage/prefix/learntok/tenants/t1/"));
        let target = format!("{}?{}", url.path(), url.query().unwrap());
        let headers = HashMap::from([("host".into(), "s3.example.com:9443".into())]);
        assert!(verify("GET", &target, &headers, &[], 1369353600));
        assert!(!verify("DELETE", &target, &headers, &[], 1369353600));
        assert!(!verify("GET", &target.replace("Expires=60", "Expires=61"), &headers, &[], 1369353600));
        assert!(!verify("GET", &target, &headers, &[], 1369353661));
        assert!(!verify("GET", &target, &HashMap::from([("host".into(), "evil.example".into())]), &[], 1369353600));
    }
    for bucket in ["../evil", "//evil.example", "bad?query", "bad#fragment", "user@evil"] {
        assert!(S3Store::new(S3Config { bucket: bucket.into(), ..store.config.clone() }).is_err());
    }
    for endpoint in ["https://user:sentinel@host", "https://host?sentinel", "https://host#sentinel"] {
        let error = S3Store::new(S3Config { endpoint: endpoint.into(), ..store.config.clone() }).unwrap_err();
        assert!(!format!("{error:#?} {error}").contains("sentinel"));
    }
    for key in [
        "../evil",
        "//evil.example",
        "a/../b",
        "tenants/t1/空 格%+.wav",
        "tenants/t1/a b",
        "tenants/t1/a%20b",
        "tenants/t1/a+b",
    ] {
        assert!(store.presign_get_url_at(key, 60, time).is_empty());
    }
}

#[test]
fn signed_payload_header_and_bytes_cannot_be_changed() {
    let store = store();
    let (target, _, host) = store.resolve_target("tenants/t1/a").unwrap();
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"original"));
    let date = jiff::Timestamp::from_second(1369353600).unwrap();
    let signed = rusty_s3::signing::sign(
        &date,
        rusty_s3::Method::Put,
        target.parse().unwrap(),
        &store.config.access_key_id,
        &store.config.secret_access_key,
        None,
        &store.config.region,
        60,
        std::iter::empty(),
        [("x-amz-checksum-sha256", hash.as_str())].into_iter(),
    );
    let target = format!("{}?{}", signed.path(), signed.query().unwrap());
    let mut headers = HashMap::from([("host".into(), host), ("x-amz-checksum-sha256".into(), hash)]);
    assert!(verify("PUT", &target, &headers, b"original", 1369353600));
    assert!(!verify("PUT", &target, &headers, b"tampered", 1369353600));
    headers.insert(
        "x-amz-checksum-sha256".into(),
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"tampered")),
    );
    assert!(!verify("PUT", &target, &headers, b"tampered", 1369353600));
}

#[tokio::test]
async fn pagination_cycles_retain_cleanup_responsibility() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for versions in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut b = [0; 4096];
                    let n = socket.read(&mut b).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&b[..n]);
                }
                let count = seen.fetch_add(1, Ordering::SeqCst);
                let marker = if count.is_multiple_of(2) { "a" } else { "b" };
                let body = if versions {
                    format!(
                        "<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>tenants/t1/{marker}</NextKeyMarker><NextVersionIdMarker>{marker}</NextVersionIdMarker></ListVersionsResult>"
                    )
                } else {
                    format!(
                        "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>{marker}</NextContinuationToken></ListBucketResult>"
                    )
                };
                socket
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let store = S3Store::new(S3Config { endpoint, ..store().config }).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            if versions {
                store.purge_prefix("tenants/t1/").await
            } else {
                store.list_prefix("tenants/t1/").await.map(|_| ())
            }
        })
        .await
        .expect("cyclic listing must stop without waiting for transport failure");
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3, "a-b-a must fail before requesting another page");
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn streaming_range_requests_bind_signature_version_and_response_geometry() {
    use memoswish_core::assets::ObjectVersion;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (status, extra, body, success) in [
        ("206 Partial Content", "Content-Range: bytes 0-2/3\r\nContent-Length: 3\r\n", "abc", true),
        ("200 OK", "Content-Range: bytes 0-2/3\r\nContent-Length: 3\r\n", "abc", false),
        ("206 Partial Content", "Content-Range: bytes 1-3/3\r\nContent-Length: 3\r\n", "abc", false),
        ("206 Partial Content", "Content-Range: bytes 0-2/3\r\nContent-Length: 4\r\n", "abcd", false),
        ("206 Partial Content", "Content-Range: bytes 0-2/3\r\nContent-Length: 3\r\n", "ab", false),
        (
            "206 Partial Content",
            "Content-Range: bytes 0-2/3\r\nTransfer-Encoding: chunked\r\n",
            "4\r\nabcd\r\n0\r\n\r\n",
            false,
        ),
        ("302 Found", "Location: http://127.0.0.1:1/SECRET_SENTINEL\r\nContent-Length: 0\r\n", "", false),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for method in ["HEAD", "GET"] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut bytes = [0; 1024];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&bytes[..n]);
                }
                let request = String::from_utf8(request).unwrap();
                let target = request.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                let headers: HashMap<_, _> = request
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                    .collect();
                assert!(
                    verify(method, target, &headers, &[], Utc::now().timestamp()),
                    "fixture must independently verify the signature"
                );
                assert!(target.contains("versionId=v%2Bold"));
                if method == "HEAD" {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nETag: \"stored\"\r\nx-amz-version-id: v+old\r\nContent-Length: 3\r\nConnection: close\r\n\r\n").await.unwrap();
                } else {
                    assert_eq!(headers["range"], "bytes=0-2");
                    assert_eq!(headers["if-match"], "\"stored\"");
                    let params: HashMap<_, _> = reqwest::Url::parse(&format!("http://localhost{target}"))
                        .unwrap()
                        .query_pairs()
                        .into_owned()
                        .collect();
                    assert_eq!(params["X-Amz-SignedHeaders"], "host;if-match;range");
                    let mut changed = headers.clone();
                    changed.insert("range".into(), "bytes=1-2".into());
                    assert!(!verify(method, target, &changed, &[], Utc::now().timestamp()));
                    let response = format!(
                        "HTTP/1.1 {status}\r\n{extra}Content-Type: image/png\r\nETag: \"stored\"\r\nx-amz-version-id: v+old\r\nConnection: close\r\n\r\n{body}"
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });
        let store = S3Store::new(S3Config { endpoint, ..store().config }).unwrap();
        assert!(store.open_delivery("tenants/t1/a", &ObjectVersion::Unknown, 3).await.is_err());
        let mut reader =
            store.open_delivery("tenants/t1/a", &ObjectVersion::VersionId("v+old".into()), 3).await.unwrap().unwrap();
        let result = reader.read_at(0, 3).await;
        if success {
            assert_eq!(result.unwrap(), b"abc");
        } else {
            let error = result.unwrap_err();
            assert!(!format!("{error:?}").contains("SECRET_SENTINEL"));
        }
        server.await.unwrap();
    }
}
