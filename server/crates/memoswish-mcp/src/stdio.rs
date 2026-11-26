//! SDK 行编码及服务生命周期；stdout 专用于协议，输入先经过公共安全边界。

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures::{SinkExt, StreamExt};
use memoswish_core::Principal;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::Transport;
use rmcp::transport::async_rw::JsonRpcMessageCodec;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, FramedRead, FramedWrite, LinesCodec, LinesCodecError};

use crate::protocol::{MAX_MESSAGE_BYTES, request_id, validate};
use crate::server::{Handler, McpServer};

/// 行错误作为帧交给安全边界，只有实际读取错误才能结束 FramedRead。
struct RecoverableLines(LinesCodec);

impl Decoder for RecoverableLines {
    type Item = Result<String, LinesCodecError>;
    type Error = std::io::Error;

    fn decode(&mut self, bytes: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(self.0.decode(bytes).map(|line| line.map(Ok)).unwrap_or_else(|error| Some(Err(error))))
    }

    fn decode_eof(&mut self, bytes: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(self.0.decode_eof(bytes).map(|line| line.map(Ok)).unwrap_or_else(|error| Some(Err(error))))
    }
}

/// 复用有界行解码与 SDK 响应编码，额外拒绝畸形业务 envelope。
struct CheckedTransport<R, W> {
    reader: FramedRead<R, RecoverableLines>,
    writer: Arc<Mutex<FramedWrite<W, JsonRpcMessageCodec<ServerJsonRpcMessage>>>>,
    clean_eof: Arc<AtomicBool>,
    active_calls: crate::control::ActiveCalls,
    authority: String,
}

impl<R, W> Transport<rmcp::RoleServer> for CheckedTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = std::io::Error;

    fn send(
        &mut self,
        message: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let writer = self.writer.clone();
        async move { writer.lock().await.send(message).await.map_err(|_| std::io::Error::other("MCP output failed")) }
    }

    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        while let Some(frame) = self.reader.next().await {
            // I/O 失败结束传输；行长度、UTF-8 和 JSON 失败只拒绝当前帧。
            let frame = match frame {
                Ok(Ok(line)) if line.trim().is_empty() => continue,
                Ok(Ok(line)) => serde_json::from_str::<serde_json::Value>(&line).map_err(|_| ()),
                Ok(Err(_)) => Err(()),
                Err(_) => return None,
            };
            let (id, error) = match frame {
                Ok(value) => {
                    // 控制通知的原因不参与授权，也不交给 SDK 的详细诊断。
                    if value["method"] == "notifications/cancelled" {
                        if let Some(id) = crate::protocol::cancellation_id(&value)
                            && validate(value.clone()).is_ok()
                        {
                            self.active_calls.cancel(self.authority.clone(), id);
                        }
                        continue;
                    }
                    let id = request_id(&value);
                    match validate(value) {
                        Ok(mut message) => {
                            // 在读取下一帧前建立所有权，SDK 异步调度前到达的取消也能被保存。
                            if let ClientJsonRpcMessage::Request(request) = &mut message
                                && let rmcp::model::ClientRequest::CallToolRequest(call) = &mut request.request
                            {
                                match self.active_calls.register(self.authority.clone(), request.id.clone()) {
                                    Ok(active) => {
                                        call.extensions.insert(Arc::new(active));
                                    }
                                    Err(error) => {
                                        if self
                                            .writer
                                            .lock()
                                            .await
                                            .send(ServerJsonRpcMessage::error(error, id))
                                            .await
                                            .is_err()
                                        {
                                            return None;
                                        }
                                        continue;
                                    }
                                }
                            }
                            return Some(message);
                        }
                        Err(error) => (id, error),
                    }
                }
                // 不向客户端或日志暴露失败帧及解码器诊断。
                Err(_) => (None, rmcp::ErrorData::parse_error("invalid JSON", None)),
            };
            if self.writer.lock().await.send(ServerJsonRpcMessage::error(error, id)).await.is_err() {
                return None;
            }
        }
        self.clean_eof.store(true, Ordering::Relaxed);
        None
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.writer.lock().await.close().await.map_err(|_| std::io::Error::other("MCP output failed"))
    }
}

/// 运行 SDK 握手与请求生命周期，直到 EOF。输入输出由服务任务拥有。
pub async fn serve<R, W>(server: &McpServer, principal: &Principal, reader: R, writer: W) -> std::io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let clean_eof = Arc::new(AtomicBool::new(false));
    let authority = format!("stdio:{}", memoswish_core::ids::new_id());
    let transport = CheckedTransport {
        reader: FramedRead::new(reader, RecoverableLines(LinesCodec::new_with_max_length(MAX_MESSAGE_BYTES))),
        writer: Arc::new(Mutex::new(FramedWrite::new(writer, JsonRpcMessageCodec::new()))),
        clean_eof: clean_eof.clone(),
        active_calls: server.active_calls.clone(),
        authority: authority.clone(),
    };
    let service = match rmcp::serve_server(
        Handler { server: server.clone(), stdio_principal: Some(principal.clone()), stdio_authority: Some(authority) },
        transport,
    )
    .await
    {
        Ok(service) => service,
        // 尚未握手的客户端也可正常关闭；只认可读端真实 EOF，不能吞掉 I/O 或握手错误。
        Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) if clean_eof.load(Ordering::Relaxed) => {
            return Ok(());
        }
        Err(_) => return Err(std::io::Error::other("MCP initialization failed")),
    };
    service.waiting().await.map_err(|_| std::io::Error::other("MCP service failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tests::test_server;
    use rmcp::{ServiceExt, model::CallToolRequestParams};

    #[tokio::test]
    async fn stdio_roundtrip() {
        let server = test_server().await;
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(peer);
        let task = tokio::spawn(async move {
            serve(&server, &Principal::local_owner("stdio"), read, write).await.unwrap();
        });
        let client = ().serve(client).await.unwrap();
        assert_eq!(client.peer_info().unwrap().protocol_version.as_str(), "2025-11-25");
        client.peer().send_request(rmcp::model::ClientRequest::PingRequest(Default::default())).await.unwrap();
        let tools = client.peer().list_tools(Default::default()).await.unwrap();
        assert_eq!(serde_json::to_value(tools).unwrap(), crate::tools::list_tools_json());
        let result = client.peer().call_tool(CallToolRequestParams::new("deck_list")).await.unwrap();
        assert_eq!(result.is_error, Some(false));
        client.cancel().await.unwrap();
        task.await.unwrap();
    }
    #[tokio::test]
    async fn malformed_stdio_messages_are_safe_and_cannot_execute_tools() {
        use serde_json::{Value, json};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let server = test_server().await;
        let services = server.services.clone();
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(peer);
        let task = tokio::spawn(async move {
            serve(&server, &Principal::local_owner("stdio"), read, write).await.unwrap();
        });
        let (read, mut write) = tokio::io::split(client);
        let mut read = BufReader::new(read);
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}});
        write.write_all(format!("{init}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        read.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["result"]["protocolVersion"], "2025-11-25");
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        for value in [
            json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"deck_create","arguments":{"title":"must not exist"}}}),
            json!({"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"deck_create","arguments":{"title":"must not exist"}}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","result":{},"params":{"name":"deck_create","arguments":{"title":"must not exist"}}}),
        ] {
            write.write_all(format!("{value}\n").as_bytes()).await.unwrap();
            line.clear();
            read.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["error"]["code"],
                crate::protocol::codes::INVALID_REQUEST
            );
        }
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n").await.unwrap();
        line.clear();
        read.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["result"], json!({}));
        write.write_all(b"{\"S28_SECRET_SENTINEL\":bad}\n").await.unwrap();
        line.clear();
        read.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["error"]["code"], crate::protocol::codes::PARSE_ERROR);
        assert!(!line.contains("S28_SECRET_SENTINEL"));
        for (prefix, id) in [(b"".as_slice(), 4), (b"\n\r\n  \n".as_slice(), 5)] {
            write.write_all(prefix).await.unwrap();
            write
                .write_all(format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\"}}\n").as_bytes())
                .await
                .unwrap();
            line.clear();
            assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
            let response: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(response["id"], id);
            assert_eq!(response["result"], json!({}));
        }
        write.shutdown().await.unwrap();
        drop(write);
        task.await.unwrap();
        assert!(services.list_decks(&Principal::local_owner("test")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn bounded_lines_recover_from_oversize_and_invalid_utf8_but_end_on_io_failure() {
        use tokio::io::AsyncWriteExt;
        let (mut write, read) = tokio::io::duplex(16);
        let task = tokio::spawn(async move {
            write.write_all(b"123456789\n\xff\nping\n").await.unwrap();
        });
        let mut reader = FramedRead::new(read, RecoverableLines(LinesCodec::new_with_max_length(4)));
        assert!(reader.next().await.unwrap().unwrap().is_err());
        assert!(reader.next().await.unwrap().unwrap().is_err());
        assert_eq!(reader.next().await.unwrap().unwrap().unwrap(), "ping");
        assert!(reader.next().await.is_none());
        task.await.unwrap();

        struct FailedRead;
        impl AsyncRead for FailedRead {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("synthetic read failure")))
            }
        }
        let mut transport = CheckedTransport {
            reader: FramedRead::new(FailedRead, RecoverableLines(LinesCodec::new_with_max_length(4))),
            writer: Arc::new(Mutex::new(FramedWrite::new(tokio::io::sink(), JsonRpcMessageCodec::new()))),
            clean_eof: Arc::new(AtomicBool::new(false)),
            active_calls: Default::default(),
            authority: "stdio:test".into(),
        };
        assert!(transport.receive().await.is_none());
        assert!(!transport.clean_eof.load(Ordering::Relaxed), "read failure must not be classified as clean EOF");
        let error = serve(&test_server().await, &Principal::local_owner("stdio"), FailedRead, tokio::io::sink())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "MCP initialization failed");
    }

    #[tokio::test]
    async fn pre_initialize_eof_is_normal_but_invalid_handshake_is_an_error() {
        let server = test_server().await;
        let principal = Principal::local_owner("stdio");
        for input in [b"".as_slice(), b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".as_slice()] {
            serve(&server, &principal, input, tokio::io::sink()).await.unwrap();
        }
        let invalid = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n".as_slice();
        let error = serve(&server, &principal, invalid, tokio::io::sink()).await.unwrap_err();
        assert_eq!(error.to_string(), "MCP initialization failed");
        let ping = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".as_slice();
        let (writer, peer) = tokio::io::duplex(64);
        drop(peer);
        let error = serve(&server, &principal, ping, writer).await.unwrap_err();
        assert_eq!(error.to_string(), "MCP initialization failed");
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test(flavor = "current_thread")]
    async fn buffered_request_and_cancel_precede_handler_and_leave_no_import_responsibility() {
        let server = crate::server::tests::test_server().await;
        let services = server.services.clone();
        let calls = server.active_calls.clone();
        let principal = Principal::local_owner("stdio");
        let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"deck_import","arguments":{"pack":memoswish_protocol::examples::sample_deck_pack(),"request_id":"buffered-cancel","auto_tts":true}}});
        let buffered = format!(
            "{call}\n{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":2,\"reason\":\"SECRET_REASON_SENTINEL\"}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}}\n"
        );

        // 直接逐帧读取且不运行 handler，确定性证明守卫先于取消存在。
        let mut transport = CheckedTransport {
            reader: FramedRead::new(
                buffered.as_bytes(),
                RecoverableLines(LinesCodec::new_with_max_length(MAX_MESSAGE_BYTES)),
            ),
            writer: Arc::new(Mutex::new(FramedWrite::new(tokio::io::sink(), JsonRpcMessageCodec::new()))),
            clean_eof: Default::default(),
            active_calls: calls.clone(),
            authority: "stdio:buffered".into(),
        };
        let request = transport.receive().await.unwrap();
        assert!(calls.register("stdio:buffered".into(), rmcp::model::RequestId::Number(2)).is_err());
        assert!(transport.receive().await.is_some());
        let ClientJsonRpcMessage::Request(request) = request else { panic!("expected request") };
        let rmcp::model::ClientRequest::CallToolRequest(request) = request.request else {
            panic!("expected tool call")
        };
        let active = request.extensions.get::<Arc<crate::control::ActiveCall>>().unwrap();
        assert!(active.control.checkpoint().is_err());
        drop(request);
        assert!(calls.register("stdio:buffered".into(), rmcp::model::RequestId::Number(2)).is_ok());

        // 真实 SDK 服务同样一次写入请求和取消，不等待 handler 入口或进度通知。
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(peer);
        let service =
            tokio::spawn(async move { serve(&server, &Principal::local_owner("stdio"), read, write).await.unwrap() });
        let (read, mut write) = tokio::io::split(client);
        let mut read = BufReader::new(read);
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"buffered\",\"version\":\"1\"}}}\n").await.unwrap();
        let mut line = String::new();
        read.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 1);
        write
            .write_all(
                format!("{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n{buffered}").as_bytes(),
            )
            .await
            .unwrap();
        let mut saw_call = false;
        let mut saw_ping = false;
        for _ in 0..2 {
            line.clear();
            assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
            assert!(!line.contains("SECRET_REASON_SENTINEL"));
            let response: Value = serde_json::from_str(&line).unwrap();
            match response["id"].as_i64().unwrap() {
                2 => {
                    assert_eq!(response["result"]["isError"], true);
                    assert_eq!(
                        response["result"]["content"][0]["text"],
                        "[temporarily_unavailable] temporarily unavailable"
                    );
                    saw_call = true;
                }
                3 => saw_ping = true,
                _ => panic!("unexpected response"),
            }
        }
        assert!(saw_call && saw_ping);
        services.operations.close();
        services.operations.wait().await;
        assert!(services.list_decks(&principal).await.unwrap().is_empty());
        let repo = services.content.import_repository();
        let authority = memoswish_core::imports::ImportAuthority::capture(&principal, None);
        assert!(repo.import_status(&authority, "buffered-cancel").await.unwrap().is_none());
        assert!(repo.pending_imports(None).await.unwrap().is_empty());
        assert_eq!(repo.held_import_usage("local", &memoswish_auth::quota::current_period()).await.unwrap(), 0);
        drop((read, write));
        service.await.unwrap();
    }

    struct Gate {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl memoswish_core::rate_limit::RateLimiter for Gate {
        async fn check(&self, _: &str, _: f64) -> memoswish_core::CoreResult<()> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }
    #[tokio::test]
    async fn long_call_accepts_ping_and_cancellation_with_zero_progress_token() {
        let mut server = crate::server::tests::test_server().await;
        let gate = Arc::new(Gate { entered: tokio::sync::Notify::new(), release: tokio::sync::Notify::new() });
        server.services.limiter = gate.clone();
        let services = server.services.clone();
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(peer);
        let service = tokio::spawn(async move {
            serve(&server, &Principal::local_owner("stdio"), read, write).await.unwrap();
        });
        let (read, mut write) = tokio::io::split(client);
        let mut read = BufReader::new(read);
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw-independent","version":"1"}}});
        write.write_all(format!("{init}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        read.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["result"]["protocolVersion"], "2025-06-18");
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"deck_import","_meta":{"progressToken":0},"arguments":{"pack":memoswish_protocol::examples::sample_deck_pack(),"request_id":"stdio-cancel","auto_tts":false}}});
        write.write_all(format!("{call}\n").as_bytes()).await.unwrap();
        gate.entered.notified().await;
        line.clear();
        read.read_line(&mut line).await.unwrap();
        let update: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(update["method"], "notifications/progress");
        assert_eq!(update["params"]["progressToken"], 0);
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n").await.unwrap();
        line.clear();
        read.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 3);
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}\n{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"}\n").await.unwrap();
        line.clear();
        read.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 4);
        gate.release.notify_one();
        line.clear();
        read.read_line(&mut line).await.unwrap();
        let result: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(result["id"], 2);
        assert_eq!(result["result"]["isError"], true);
        assert!(services.list_decks(&Principal::local_owner("stdio")).await.unwrap().is_empty());
        drop((read, write));
        service.await.unwrap();
    }
}
