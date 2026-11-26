//! 活动调用只保存当前控制句柄，不缓存认证、不承担持久恢复。
use memoswish_application::OperationControl;
use memoswish_core::Principal;
use rmcp::model::RequestId;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

// 上限约束进程资源，键长另行限制；不通过逐出正在执行的调用释放容量。
const MAX_ACTIVE: usize = 256;
const MAX_PER_AUTHORITY: usize = 32;
const MAX_ID_BYTES: usize = 128;

#[derive(Clone, Default)]
pub(crate) struct ActiveCalls(Arc<Mutex<HashMap<(String, RequestId), OperationControl>>>);

pub(crate) fn http_authority(p: &Principal, bearer: Option<&str>) -> String {
    let identity =
        serde_json::to_vec(&(p, &p.session_access_hash, bearer.map(|b| memoswish_core::ids::sha256_hex(b.as_bytes()))))
            .expect("principal identity");
    format!("http:{}", memoswish_core::ids::sha256_hex(&identity))
}

pub(crate) struct ActiveCall {
    calls: ActiveCalls,
    key: (String, RequestId),
    pub control: OperationControl,
}

impl ActiveCalls {
    pub fn register(&self, authority: String, id: RequestId) -> Result<ActiveCall, rmcp::ErrorData> {
        let mut calls = self.0.lock().unwrap();
        let key = (authority, id);
        if serde_json::to_vec(&key.1).expect("request ID").len() > MAX_ID_BYTES {
            return Err(rmcp::ErrorData::invalid_params("request ID exceeds control budget", None));
        }
        if calls.contains_key(&key) {
            return Err(rmcp::ErrorData::invalid_request("duplicate active request ID", None));
        }
        if calls.len() >= MAX_ACTIVE || calls.keys().filter(|(a, _)| a == &key.0).count() >= MAX_PER_AUTHORITY {
            return Err(rmcp::ErrorData::internal_error("active call capacity reached; retry later", None));
        }
        let control = OperationControl::new(CancellationToken::new());
        calls.insert(key.clone(), control.clone());
        Ok(ActiveCall { calls: self.clone(), key, control })
    }

    pub fn cancel(&self, authority: String, id: RequestId) {
        if let Some(control) = self.0.lock().unwrap().get(&(authority, id)) {
            control.cancel();
        }
    }
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.calls.0.lock().unwrap().remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_typed_authority_scoped_calls_do_not_evict_or_transfer_control() {
        let calls = ActiveCalls::default();
        let one = calls.register("stdio:a".into(), serde_json::from_str("1").unwrap()).unwrap();
        let text = calls.register("stdio:a".into(), serde_json::from_str("\"1\"").unwrap()).unwrap();
        assert!(calls.register("stdio:a".into(), serde_json::from_str("1").unwrap()).is_err());
        calls.cancel("stdio:b".into(), serde_json::from_str("1").unwrap());
        assert!(one.control.checkpoint().is_ok());
        calls.cancel("stdio:a".into(), serde_json::from_str("1").unwrap());
        assert!(one.control.checkpoint().is_err());
        assert!(text.control.checkpoint().is_ok());
        let mut held = vec![one, text];
        for id in 2..MAX_PER_AUTHORITY {
            held.push(calls.register("stdio:a".into(), RequestId::Number(id as i64)).unwrap());
        }
        assert!(calls.register("stdio:a".into(), RequestId::Number(999)).is_err());
        drop(held);
        assert!(calls.register("stdio:a".into(), RequestId::Number(1)).is_ok());
        let mut global = Vec::new();
        for id in 0..MAX_ACTIVE {
            global.push(calls.register(format!("http:{id}"), RequestId::Number(1)).unwrap());
        }
        assert!(calls.register("http:overflow".into(), RequestId::Number(1)).is_err());
        assert!(global.iter().skip(1).all(|call| call.control.checkpoint().is_ok()));
    }

    #[test]
    fn credentials_generations_and_transports_are_separate_namespaces() {
        let p = Principal::local_owner("same");
        assert_ne!(http_authority(&p, Some("synthetic-a")), http_authority(&p, Some("synthetic-b")));
        let mut q = p.clone();
        q.session_access_hash = Some("new-generation".into());
        assert_ne!(http_authority(&p, None), http_authority(&q, None));
        q.tenant_id = "foreign".into();
        assert_ne!(http_authority(&p, None), http_authority(&q, None));
    }
}
