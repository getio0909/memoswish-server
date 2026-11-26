//! HTTP / 云端神经网络 TTS 引擎。
//!
//! 兼容两类响应格式：
//! 1. OpenAI `/v1/audio/speech` 风格二进制 WAV 响应：自动解析 WAV 时长并按字符权重估算逐词时间戳；
//! 2. `application/json` 响应（`{ "audio_base64": "...", "words": [...] }`）：直接使用云端返回的原生词边界时间戳。

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use memoswish_core::tts::{TtsEngine, TtsOutput, TtsRequest, VoiceInfo};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::WordTimestamp;
use serde::{Deserialize, Serialize};

use super::estimate_word_timestamps;
use crate::segment::tokenize;
use crate::wav::wav_duration_ms;

/// HTTP TTS 引擎配置。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpTtsConfig {
    /// 引擎唯一标识，默认 `http`，可配置多个（例如 `openai-tts`、`cloud-tts`）。
    pub id: String,
    /// HTTP 合成端点 URL，例如 `https://api.openai.com/v1/audio/speech`。
    pub endpoint: String,
    /// 可选的 Bearer API Key。
    pub api_key: Option<String>,
    /// 模型名称，例如 `tts-1` 或 `gpt-4o-mini-tts`。
    pub model: String,
    /// 默认音色名称，例如 `alloy`。
    pub default_voice: String,
    /// 每字符计费倍率（商业云端引擎默认为 1）。
    pub cost_per_char: u32,
    /// 请求超时时间（秒），默认 30。
    pub timeout_secs: u64,
}

impl std::fmt::Debug for HttpTtsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 端点及模型也可能内嵌凭据，调试输出只披露类型。
        f.debug_struct("HttpTtsConfig").finish_non_exhaustive()
    }
}

impl Default for HttpTtsConfig {
    fn default() -> Self {
        Self {
            id: "http".into(),
            endpoint: "https://api.openai.com/v1/audio/speech".into(),
            api_key: None,
            model: "tts-1".into(),
            default_voice: "alloy".into(),
            cost_per_char: 1,
            timeout_secs: 30,
        }
    }
}

/// 发送给 HTTP TTS 端点的请求体（兼容 OpenAI `/v1/audio/speech`）。
#[derive(Debug, Serialize)]
struct SpeechPayload<'a> {
    model: &'a str,
    input: &'a str,
    voice: &'a str,
    response_format: &'a str,
    speed: f32,
    language: &'a str,
}

/// 带原生词边界的 JSON 响应结构。
#[derive(Debug, Deserialize)]
struct JsonSpeechResponse {
    audio_base64: String,
    #[serde(default)]
    duration_ms: Option<u32>,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    extension: Option<String>,
    #[serde(default, deserialize_with = "deserialize_words")]
    words: Vec<WordTimestamp>,
}

/// HTTP / 云端神经网络 TTS 引擎。
#[derive(Clone)]
pub struct HttpTts {
    observer: std::sync::Arc<dyn memoswish_core::observability::Observer>,
    cfg: HttpTtsConfig,
    client: Option<reqwest::Client>,
}

impl std::fmt::Debug for HttpTts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTts").finish_non_exhaustive()
    }
}
impl HttpTts {
    pub fn with_observer(mut self, observer: std::sync::Arc<dyn memoswish_core::observability::Observer>) -> Self {
        self.observer = observer;
        self
    }
    /// 从配置创建 HTTP TTS 引擎。
    pub fn new(cfg: HttpTtsConfig) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(cfg.timeout_secs.clamp(1, 60)))
            .build()
            .ok();
        Self { cfg, client, observer: memoswish_core::observability::noop() }
    }

    /// 返回当前引擎配置引用。
    pub fn config(&self) -> &HttpTtsConfig {
        &self.cfg
    }
}

#[async_trait]
impl TtsEngine for HttpTts {
    fn external_transfer(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        &self.cfg.id
    }

    fn cost_per_char(&self) -> u32 {
        self.cfg.cost_per_char
    }

    fn cache_namespace(&self) -> String {
        memoswish_core::ids::sha256_hex(
            serde_json::json!([
                "speech-metadata-v2",
                self.cfg.id,
                self.cfg.endpoint,
                self.cfg.model,
                self.cfg.default_voice
            ])
            .to_string()
            .as_bytes(),
        )
    }

    fn voices(&self) -> Vec<VoiceInfo> {
        vec![VoiceInfo {
            id: "default".into(),
            language: "*".into(),
            description: "Configured voice; availability unchecked".into(),
        }]
    }

    async fn synthesize(&self, req: &TtsRequest) -> CoreResult<TtsOutput> {
        self.prepare_execution(req).await?.await
    }

    async fn prepare_execution<'a>(
        &'a self,
        req: &'a TtsRequest,
    ) -> CoreResult<memoswish_core::tts::PreparedSpeech<'a>> {
        req.validate()?;
        let permit = super::EXECUTIONS
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("speech execution capacity exhausted".into()))?;
        Ok(Box::pin(self.execute(req, permit)))
    }
}

impl HttpTts {
    async fn execute(&self, req: &TtsRequest, permit: tokio::sync::SemaphorePermit<'static>) -> CoreResult<TtsOutput> {
        let tokens = tokenize(&req.text);
        if tokens.is_empty() {
            return Err(CoreError::invalid("nothing to synthesize"));
        }
        use memoswish_core::observability::{Operation, Outcome};
        let mut observation = self.observer.start(Operation::TtsHttp);
        let result = async {
            let voice = if req.voice.is_empty() || req.voice == "default" {
                self.cfg.default_voice.as_str()
            } else {
                req.voice.as_str()
            };
            let payload = SpeechPayload {
                model: &self.cfg.model,
                input: &req.text,
                voice,
                response_format: "wav",
                speed: req.speed.clamp(0.25, 4.0),
                language: &req.language,
            };

            let mut builder = self
                .client
                .as_ref()
                .ok_or_else(|| CoreError::Unavailable("http tts client unavailable".into()))?
                .post(&self.cfg.endpoint)
                .json(&payload);
            if let Some(key) = self.cfg.api_key.as_deref().filter(|k| !k.is_empty()) {
                builder = builder.bearer_auth(key);
            }
            let mut resp = builder.send().await.map_err(|error| {
                observation.finish(if error.is_timeout() { Outcome::Timeout } else { Outcome::TransportError });
                CoreError::Unavailable("http tts request failed".into())
            })?;
            if !resp.status().is_success() {
                observation.finish(Outcome::HttpError);
                let status = resp.status();
                return Err(CoreError::Unavailable(format!("http tts failed with status {status}")));
            }

            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            // JSON 的 base64 膨胀与时序也必须有界，不先缓冲无限响应再校验。
            let limit =
                if content_type.contains("application/json") { super::SPEECH_JSON_BYTES } else { super::AUDIO_BYTES };
            if resp.content_length().is_some_and(|n| n > limit as u64) {
                return Err(CoreError::Unavailable("http tts response exceeds size limit".into()));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = resp.chunk().await.map_err(|error| {
                observation.finish(if error.is_timeout() { Outcome::Timeout } else { Outcome::TransportError });
                CoreError::Unavailable("http tts response read failed".into())
            })? {
                if chunk.len() > limit - bytes.len() {
                    return Err(CoreError::Unavailable("http tts response exceeds size limit".into()));
                }
                bytes.extend_from_slice(&chunk);
            }

            let text = req.text.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                memoswish_content::processing::WorkBudget::default()
                    .scope(|| parse_response(&bytes, &text, &content_type))
            })
            .await
            .map_err(|_| CoreError::Unavailable("speech decoder interrupted".into()))?
        }
        .await;
        observation.finish(if result.is_ok() { Outcome::Returned } else { Outcome::InvalidResponse });
        result
    }
}

/// 同一生产解析器供普通响应、负例和 fuzz 调用。
pub fn parse_response(bytes: &[u8], text: &str, content_type: &str) -> CoreResult<TtsOutput> {
    if bytes.len() > super::SPEECH_JSON_BYTES || text.len() > 8000 || text.chars().count() > 2000 {
        return Err(CoreError::invalid("speech decode envelope exceeded"));
    }
    if content_type.contains("application/json") || bytes.first() == Some(&b'{') {
        let parsed: JsonSpeechResponse = serde_json::from_reader(memoswish_content::processing::BudgetReader {
            reader: std::io::Cursor::new(bytes),
            budget: memoswish_content::processing::WorkBudget::default(),
        })
        .map_err(|_| CoreError::invalid("invalid http tts json response"))?;
        if parsed.audio_base64.len() > super::AUDIO_BYTES.div_ceil(3) * 4 {
            return Err(CoreError::invalid("speech base64 exceeds limit"));
        }
        let audio = base64::engine::general_purpose::STANDARD
            .decode(parsed.audio_base64.trim())
            .map_err(|_| CoreError::internal("invalid base64 audio in http tts response"))?;
        if audio.len() > super::AUDIO_BYTES
            || parsed.mime.as_deref().is_some_and(|m| m != "audio/wav")
            || parsed.extension.as_deref().is_some_and(|e| e != "wav")
        {
            return Err(CoreError::Unsupported("provider speech must be bounded PCM WAV".into()));
        }
        let duration_ms = wav_duration_ms(&audio).ok_or_else(|| CoreError::invalid("invalid provider PCM WAV"))?;
        if parsed.duration_ms.is_some_and(|duration| duration != duration_ms) {
            return Err(CoreError::invalid("provider duration disagrees with PCM"));
        }
        let quality = if parsed.words.is_empty() {
            memoswish_protocol::AlignmentQuality::Estimated
        } else {
            memoswish_protocol::AlignmentQuality::Native
        };
        let words = if parsed.words.is_empty() { estimate_word_timestamps(text, duration_ms) } else { parsed.words };
        super::validate_timestamps(text, &words, duration_ms)?;
        return Ok(TtsOutput {
            alignment_quality: Some(quality),
            audio_kind: Some(memoswish_protocol::AudioKind::Speech),
            provenance: None,
            audio,
            mime: parsed.mime.unwrap_or_else(|| "audio/wav".into()),
            extension: parsed.extension.unwrap_or_else(|| "wav".into()),
            duration_ms,
            words,
        });
    }

    let duration_ms =
        wav_duration_ms(bytes).ok_or_else(|| CoreError::internal("http tts did not return a valid WAV stream"))?;
    let quality = memoswish_protocol::AlignmentQuality::Estimated;
    let words = estimate_word_timestamps(text, duration_ms);
    super::validate_timestamps(text, &words, duration_ms)?;
    Ok(TtsOutput {
        alignment_quality: Some(quality),
        audio_kind: Some(memoswish_protocol::AudioKind::Speech),
        provenance: None,
        audio: bytes.to_vec(),
        mime: "audio/wav".into(),
        extension: "wav".into(),
        duration_ms,
        words,
    })
}

fn deserialize_words<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<WordTimestamp>, D::Error> {
    struct Words;
    impl<'de> serde::de::Visitor<'de> for Words {
        type Value = Vec<WordTimestamp>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("at most 8000 word timestamps")
        }
        fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
            let mut words = Vec::new();
            while let Some(word) = sequence.next_element::<WordTimestamp>()? {
                memoswish_content::processing::checkpoint(1).map_err(serde::de::Error::custom)?;
                if words.len() == 8000 || word.text.len() > 8192 {
                    return Err(serde::de::Error::custom("word timestamp limit exceeded"));
                }
                words.push(word);
            }
            Ok(words)
        }
    }
    deserializer.deserialize_seq(Words)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::wav::{SAMPLE_RATE, encode_wav, tone};

    /// 启动本地模拟 HTTP TTS 服务，根据请求中的音色分支返回二进制 WAV 或带原生词边界的 JSON。
    async fn spawn_mock_tts_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let header_end = loop {
                        let n = match stream.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };
                    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let content_len: usize = header_text
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") { v.trim().parse().ok() } else { None }
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_len {
                        let n = match stream.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body_json: serde_json::Value =
                        serde_json::from_slice(&buf[header_end..header_end + content_len]).unwrap_or_default();
                    let wav = encode_wav(&tone(440.0, 800, 0.4, SAMPLE_RATE), SAMPLE_RATE);

                    if body_json.get("voice").and_then(|v| v.as_str()) == Some("json-voice") {
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&wav);
                        let resp_body = serde_json::json!({
                            "audio_base64": b64,
                            "duration_ms": 800,
                            "words": [
                                { "text": "Hello", "start_ms": 50, "end_ms": 380, "char_start": 0, "char_end": 5 },
                                { "text": "world", "start_ms": 400, "end_ms": 760, "char_start": 6, "char_end": 11 }
                            ]
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            resp_body.len(),
                            resp_body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: audio/wav\r\nContent-Length: {}\r\n\r\n",
                            wav.len()
                        );
                        let _ = stream.write_all(header.as_bytes()).await;
                        let _ = stream.write_all(&wav).await;
                    }
                });
            }
        });

        format!("http://{addr}/v1/audio/speech")
    }

    #[tokio::test]
    async fn http_tts_supports_wav_and_json_word_boundaries() {
        let endpoint = spawn_mock_tts_server().await;
        let engine = HttpTts::new(HttpTtsConfig {
            id: "openai-tts".into(),
            endpoint,
            api_key: Some("sk-test-token".into()),
            model: "tts-1".into(),
            default_voice: "alloy".into(),
            cost_per_char: 2,
            timeout_secs: 10,
        });
        assert_eq!(engine.id(), "openai-tts");
        assert_eq!(engine.cost_per_char(), 2);

        // 1. 测试二进制 WAV 响应与自动词级时间戳估算。
        let wav_out = engine
            .synthesize(&TtsRequest {
                text: "Hello world".into(),
                language: "en-US".into(),
                voice: "default".into(),
                speed: 1.0,
            })
            .await
            .unwrap();
        assert_eq!(wav_out.duration_ms, 800);
        assert_eq!(wav_out.mime, "audio/wav");
        assert_eq!(wav_out.words.len(), 2);
        assert_eq!(wav_out.words[0].text, "Hello");
        assert_eq!(wav_out.words[1].text, "world");

        // 2. 测试带原生词边界的 JSON 响应。
        let json_out = engine
            .synthesize(&TtsRequest {
                text: "Hello world".into(),
                language: "en-US".into(),
                voice: "json-voice".into(),
                speed: 1.0,
            })
            .await
            .unwrap();
        assert_eq!(json_out.duration_ms, 800);
        assert_eq!(json_out.words.len(), 2);
        assert_eq!((json_out.words[0].start_ms, json_out.words[0].end_ms), (50, 380));
        assert_eq!((json_out.words[1].start_ms, json_out.words[1].end_ms), (400, 760));
    }
}

#[cfg(test)]
mod publication_security_tests {
    use super::*;
    #[test]
    fn provider_debug_and_configuration_fingerprint_never_expose_credentials() {
        let mut config = HttpTtsConfig {
            endpoint: "https://SECRET_SENTINEL.invalid/?key=SECRET_SENTINEL".into(),
            api_key: Some("SECRET_SENTINEL".into()),
            ..Default::default()
        };
        let a = HttpTts::new(config.clone());
        let identity = a.cache_namespace();
        assert!(!format!("{config:?} {a:?} {identity}").contains("SECRET_SENTINEL"));
        config.api_key = Some("rotated".into());
        assert_eq!(identity, HttpTts::new(config.clone()).cache_namespace());
        config.model.push('x');
        assert_ne!(identity, HttpTts::new(config).cache_namespace());
    }
}

#[cfg(test)]
mod failure_security_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn status_body_endpoint_and_oversized_response_do_not_escape_errors() {
        for oversized in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 8192];
                let _ = socket.read(&mut request).await.unwrap();
                let body = "SECRET_SENTINEL";
                let response = if oversized {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: audio/wav\r\nConnection: close\r\n\r\n",
                        90 * 1024 * 1024 + 1
                    )
                } else {
                    format!("HTTP/1.1 500 Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                };
                socket.write_all(response.as_bytes()).await.unwrap();
            });
            let engine = HttpTts::new(HttpTtsConfig {
                endpoint: format!("http://{addr}/?key=SECRET_SENTINEL"),
                api_key: Some("SECRET_SENTINEL".into()),
                ..Default::default()
            });
            let error = engine
                .synthesize(&TtsRequest {
                    text: "hello".into(),
                    language: "en".into(),
                    voice: "default".into(),
                    speed: 1.0,
                })
                .await
                .unwrap_err();
            assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
            server.await.unwrap();
        }
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;
    #[test]
    fn provider_json_rejects_audio_words_duration_and_offsets_above_envelope() {
        let audio = crate::wav::encode_wav(&vec![0.0; 8000], 8000);
        let mut value = serde_json::json!({"audio_base64": base64::engine::general_purpose::STANDARD.encode(audio), "duration_ms": 1000});
        assert!(parse_response(&serde_json::to_vec(&value).unwrap(), "Hello world", "application/json").is_ok());
        value["duration_ms"] = 1001.into();
        assert!(parse_response(&serde_json::to_vec(&value).unwrap(), "Hello world", "application/json").is_err());
        value["duration_ms"] = 1000.into();
        let word = serde_json::json!({"text":"Hello","start_ms":0,"end_ms":1,"char_start":0,"char_end":5});
        value["words"] = serde_json::Value::Array(vec![word; 8001]);
        assert!(parse_response(&serde_json::to_vec(&value).unwrap(), "Hello world", "application/json").is_err());
        value["words"] = serde_json::json!([{"text":"Hello","start_ms":0,"end_ms":1,"char_start":0,"char_end":12}]);
        assert!(parse_response(&serde_json::to_vec(&value).unwrap(), "Hello world", "application/json").is_err());
        value["audio_base64"] = "A".repeat(super::super::AUDIO_BYTES.div_ceil(3) * 4 + 1).into();
        assert!(parse_response(&serde_json::to_vec(&value).unwrap(), "Hello world", "application/json").is_err());
    }

    #[tokio::test]
    async fn provider_redirect_is_rejected_without_contacting_destination() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let target = destination.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(stream.read(&mut [0; 8192]).await.unwrap() > 0);
            stream.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        });
        let engine = HttpTts::new(HttpTtsConfig { endpoint, ..Default::default() });
        assert!(
            engine
                .synthesize(&TtsRequest {
                    text: "Hello".into(),
                    language: "en".into(),
                    voice: "default".into(),
                    speed: 1.0
                })
                .await
                .is_err()
        );
        server.await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(25), destination.accept()).await.is_err());
    }
}
