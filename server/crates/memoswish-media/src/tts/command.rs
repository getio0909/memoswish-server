//! 命令行 TTS：调用本地可执行程序生成 WAV（stdout），例如 espeak-ng 或 piper。
//!
//! 参数模板中的占位符：`{text}`、`{voice}`、`{language}`、`{wpm}`（按 175 × speed 计算）。
//! 例：`program = "espeak-ng"`，`args = ["--stdout", "-v", "{voice}", "-s", "{wpm}", "{text}"]`。
//!
//! 文本不经 shell；已知 eSpeak 优先使用 stdin，兼容 argv 配方显式终结选项。

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use memoswish_core::tts::{TtsEngine, TtsOutput, TtsRequest, VoiceInfo};
use memoswish_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::estimate_timestamps;
use crate::segment::tokenize;
use crate::wav::{normalize_espeak_stdout, wav_duration_ms};

/// 命令行 TTS 配置。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandTtsConfig {
    /// 任意配置命令默认可能外传；仅经运营方确认的离线程序显式设为 false。
    #[serde(default = "default_external_transfer")]
    pub external_transfer: bool,
    /// 引擎 ID，默认 `command`，可配置多个（例如 `espeak`、`piper`）。
    #[serde(default = "default_id")]
    pub id: String,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// 为真时通过 stdin 传入文本（piper 需要）。
    #[serde(default)]
    pub text_via_stdin: bool,
    #[serde(default = "default_voice")]
    pub default_voice: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl std::fmt::Debug for CommandTtsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandTtsConfig").finish_non_exhaustive()
    }
}

async fn read_bounded(reader: impl AsyncRead + Unpin, limit: usize) -> CoreResult<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| CoreError::Unavailable("speech command output failed".into()))?;
    if bytes.len() > limit {
        return Err(CoreError::Unavailable("speech command output exceeds limit".into()));
    }
    Ok(bytes)
}

/// 一个期限覆盖 stdin、双管道、退出和回收；错误从不携带命令原文。
async fn run_bounded(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    timeout: u64,
    limit: usize,
) -> CoreResult<Vec<u8>> {
    if program.len() > 4096 || args.len() > 64 || args.iter().map(String::len).sum::<usize>() > 16 * 1024 {
        return Err(CoreError::invalid("speech command input exceeds envelope"));
    }
    let permit = super::EXECUTIONS
        .try_acquire()
        .map_err(|_| CoreError::Unavailable("speech execution capacity exhausted".into()))?;
    let program = program.to_owned();
    let args = args.to_vec();
    let input = input.map(<[u8]>::to_vec);
    // 独立所有者负责子进程回收；调用者取消也不能提前归还许可。
    tokio::spawn(async move {
        let _permit = permit;
        run_child(&program, &args, input.as_deref(), timeout.min(60), limit).await
    })
    .await
    .map_err(|_| CoreError::Unavailable("speech command owner interrupted".into()))?
}

async fn run_child(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    timeout: u64,
    limit: usize,
) -> CoreResult<Vec<u8>> {
    let mut command = Command::new(program);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| CoreError::Unavailable("speech executable could not start; check local installation".into()))?;
    #[cfg(unix)]
    let mut group = CommandGroup(child.id().and_then(|pid| rustix::process::Pid::from_raw(pid as i32)));
    let stdout = child.stdout.take().ok_or_else(|| CoreError::internal("speech stdout unavailable"))?;
    let stderr = child.stderr.take().ok_or_else(|| CoreError::internal("speech stderr unavailable"))?;
    let mut stdin = child.stdin.take();
    let result = tokio::time::timeout(Duration::from_secs(timeout), async {
        let send = async {
            if let Some(ref mut pipe) = stdin {
                pipe.write_all(input.unwrap_or_default())
                    .await
                    .map_err(|_| CoreError::Unavailable("speech stdin failed".into()))?;
                pipe.shutdown().await.map_err(|_| CoreError::Unavailable("speech stdin failed".into()))?;
            }
            drop(stdin.take());
            Ok::<_, CoreError>(())
        };
        let (audio, _, _, status) =
            tokio::try_join!(read_bounded(stdout, limit), read_bounded(stderr, 64 * 1024), send, async {
                child.wait().await.map_err(|_| CoreError::Unavailable("speech command wait failed".into()))
            })?;
        if !status.success() {
            return Err(CoreError::Unavailable("speech command failed; check engine and voice installation".into()));
        }
        Ok(audio)
    })
    .await;
    match result {
        Ok(Ok(audio)) => Ok(audio),
        failed => {
            #[cfg(unix)]
            group.terminate();
            let _ = child.kill().await;
            let _ = child.wait().await;
            match failed {
                Ok(Err(error)) => Err(error),
                _ => Err(CoreError::Unavailable("speech command timed out".into())),
            }
        }
    }
}

// 运行时直接取消所有者时也终止同组后代，不能只依赖异步错误分支。
#[cfg(unix)]
struct CommandGroup(Option<rustix::process::Pid>);

#[cfg(unix)]
impl CommandGroup {
    fn terminate(&mut self) {
        if let Some(group) = self.0.take() {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
    }
}

#[cfg(unix)]
impl Drop for CommandGroup {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn default_id() -> String {
    "command".into()
}
fn default_external_transfer() -> bool {
    true
}
fn default_voice() -> String {
    "en-us".into()
}
fn default_timeout() -> u64 {
    30
}

/// 命令行 TTS 引擎。
#[derive(Clone)]
pub struct CommandTts {
    observer: std::sync::Arc<dyn memoswish_core::observability::Observer>,
    cfg: CommandTtsConfig,
}

impl std::fmt::Debug for CommandTts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandTts").finish_non_exhaustive()
    }
}
impl CommandTts {
    pub fn with_observer(mut self, observer: std::sync::Arc<dyn memoswish_core::observability::Observer>) -> Self {
        self.observer = observer;
        self
    }
    pub fn new(cfg: CommandTtsConfig) -> Self {
        Self { cfg, observer: memoswish_core::observability::noop() }
    }

    /// 一个开箱即用的 espeak-ng 配置。
    pub fn espeak_ng() -> Self {
        Self::new(CommandTtsConfig {
            external_transfer: false,
            id: "espeak-ng".into(),
            program: "espeak-ng".into(),
            args: vec!["--stdout".into(), "-v".into(), "{voice}".into(), "-s".into(), "{wpm}".into(), "--stdin".into()],
            text_via_stdin: true,
            default_voice: "en-us".into(),
            timeout_secs: 30,
        })
    }

    fn is_espeak(&self) -> bool {
        std::path::Path::new(&self.cfg.program).file_name().is_some_and(|p| p == "espeak-ng")
    }

    fn can_probe_espeak(&self) -> bool {
        let suffix = if self.cfg.text_via_stdin { "--stdin" } else { "{text}" };
        self.is_espeak()
            && self.cfg.args.iter().map(String::as_str).eq(["--stdout", "-v", "{voice}", "-s", "{wpm}", suffix])
    }

    async fn available_voices(&self) -> CoreResult<Vec<String>> {
        let version =
            run_bounded(&self.cfg.program, &["--version".into()], None, self.cfg.timeout_secs, 64 * 1024).await?;
        if !String::from_utf8_lossy(&version).starts_with("eSpeak NG text-to-speech:") {
            return Err(CoreError::Unavailable("unexpected local speech engine version response".into()));
        }
        let output =
            run_bounded(&self.cfg.program, &["--voices".into()], None, self.cfg.timeout_secs, 1024 * 1024).await?;
        Self::parse_voice_listing(&output)
    }

    fn parse_voice_listing(output: &[u8]) -> CoreResult<Vec<String>> {
        let listing =
            std::str::from_utf8(output).map_err(|_| CoreError::Unavailable("invalid speech voice listing".into()))?;
        if !listing.lines().next().is_some_and(|line| line.trim_start().starts_with("Pty Language")) {
            return Err(CoreError::Unavailable("invalid speech voice listing".into()));
        }
        let mut voices = Vec::new();
        for line in listing.lines().skip(1) {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() < 5 || columns[0].parse::<u16>().is_err() {
                return Err(CoreError::Unavailable("invalid speech voice listing".into()));
            }
            let language = columns[1];
            if language.len() > 64 || !language.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(CoreError::Unavailable("invalid speech voice identifier".into()));
            }
            voices.push(language.to_string());
        }
        if voices.is_empty() || voices.len() > 1024 {
            return Err(CoreError::Unavailable("no supported speech voices installed".into()));
        }
        voices.sort();
        voices.dedup();
        Ok(voices)
    }

    async fn effective_voice(&self, req: &TtsRequest) -> CoreResult<String> {
        let selected;
        let mut voice =
            if req.voice.is_empty() || req.voice == "default" { self.cfg.default_voice.as_str() } else { &req.voice };
        if self.can_probe_espeak() {
            let voices = self.available_voices().await.map_err(|_| CoreError::SpeechEngineUnavailable)?;
            if req.voice.is_empty() || req.voice == "default" {
                selected = if req.language.starts_with("zh") {
                    "cmn".into()
                } else if req.language.starts_with("en") {
                    self.cfg.default_voice.clone()
                } else {
                    req.language.to_ascii_lowercase()
                };
                voice = &selected;
            }
            if !voices.iter().any(|v| v == voice) {
                return Err(CoreError::SpeechVoiceUnavailable);
            }
        }
        Ok(voice.to_owned())
    }

    fn render(&self, arg: &str, req: &TtsRequest, voice: &str) -> String {
        let wpm = ((175.0 * req.speed.clamp(0.5, 2.0)) as u32).to_string();
        arg.replace("{voice}", voice)
            .replace("{language}", &req.language)
            .replace("{wpm}", &wpm)
            .replace("{text}", &req.text)
    }
}

#[async_trait]
impl TtsEngine for CommandTts {
    fn id(&self) -> &str {
        &self.cfg.id
    }

    fn external_transfer(&self) -> bool {
        self.cfg.external_transfer
    }

    fn cache_namespace(&self) -> String {
        memoswish_core::ids::sha256_hex(
            serde_json::json!([
                "speech-metadata-v2",
                self.cfg.id,
                self.cfg.program,
                self.cfg.args,
                self.cfg.default_voice,
                self.cfg.text_via_stdin,
                self.cfg.external_transfer
            ])
            .to_string()
            .as_bytes(),
        )
    }

    fn voices(&self) -> Vec<VoiceInfo> {
        vec![VoiceInfo {
            id: if self.can_probe_espeak()
                && self.cfg.default_voice.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                self.cfg.default_voice.clone()
            } else {
                "default".into()
            },
            language: "*".into(),
            description: "Configured voice; availability unchecked".into(),
        }]
    }

    async fn diagnostics(&self) -> memoswish_protocol::SpeechDiagnostic {
        use memoswish_protocol::{SpeechDiagnostic, SpeechDiagnosticState};
        let (state, voices) = if self.can_probe_espeak() {
            match self.available_voices().await {
                Ok(voices) if voices.contains(&self.cfg.default_voice) => (SpeechDiagnosticState::Available, voices),
                _ => (SpeechDiagnosticState::Unavailable, vec![]),
            }
        } else {
            (SpeechDiagnosticState::Unchecked, vec![])
        };
        SpeechDiagnostic { engine: self.id().into(), configured: true, state, voices }
    }

    async fn validate_request(&self, req: &TtsRequest) -> CoreResult<()> {
        self.effective_voice(req).await.map(|_| ())
    }

    async fn synthesize(&self, req: &TtsRequest) -> CoreResult<TtsOutput> {
        self.prepare_execution(req).await?.await
    }

    async fn prepare_execution<'a>(
        &'a self,
        req: &'a TtsRequest,
    ) -> CoreResult<memoswish_core::tts::PreparedSpeech<'a>> {
        req.validate()?;
        let tokens = tokenize(&req.text);
        if tokens.is_empty() || req.text.chars().count() > 2000 {
            return Err(CoreError::invalid("provide 1..=2000 speech characters"));
        }
        let voice = self.effective_voice(req).await?;
        let mut args: Vec<String> = self.cfg.args.iter().map(|a| self.render(a, req, &voice)).collect();
        if self.can_probe_espeak() && !self.cfg.text_via_stdin {
            // 防止以连字符开头的用户文本被解释为 eSpeak 文件或控制选项。
            args.insert(args.len() - 1, "--".into());
        }
        if self.cfg.program.len() > 4096 || args.len() > 64 || args.iter().map(String::len).sum::<usize>() > 16 * 1024 {
            return Err(CoreError::invalid("speech command input exceeds envelope"));
        }
        let permit = super::EXECUTIONS
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("speech execution capacity exhausted".into()))?;
        let engine = self.clone();
        let req = req.clone();
        Ok(Box::pin(async move {
            // 预留许可从未轮询的 future 转入独立所有者，取消等待也必须完成 kill/reap。
            tokio::spawn(async move {
                let _permit = permit;
                use memoswish_core::observability::{Operation, Outcome};
                let mut observation = engine.observer.start(Operation::TtsCommand);
                let result = async {
                    let output = run_child(
                        &engine.cfg.program,
                        &args,
                        engine.cfg.text_via_stdin.then_some(req.text.as_bytes()),
                        engine.cfg.timeout_secs.min(60),
                        10 * 1024 * 1024,
                    )
                    .await?;
                    let audio = if engine.is_espeak() { normalize_espeak_stdout(output)? } else { output };
                    let duration_ms = wav_duration_ms(&audio).filter(|d| *d > 0).ok_or_else(|| {
                        CoreError::Unavailable("speech command did not produce a supported PCM WAV".into())
                    })?;
                    let words = estimate_timestamps(&tokens, duration_ms, 60, 120);
                    super::validate_timestamps(&req.text, &words, duration_ms)?;
                    Ok(TtsOutput {
                        alignment_quality: Some(memoswish_protocol::AlignmentQuality::Estimated),
                        audio_kind: Some(memoswish_protocol::AudioKind::Speech),
                        provenance: None,
                        audio,
                        mime: "audio/wav".into(),
                        extension: "wav".into(),
                        duration_ms,
                        words,
                    })
                }
                .await;
                observation.finish(match &result {
                    Ok(_) => Outcome::Returned,
                    Err(CoreError::Unavailable(message)) if message == "speech command timed out" => Outcome::Timeout,
                    Err(_) => Outcome::CommandFailure,
                });
                result
            })
            .await
            .map_err(|_| CoreError::Unavailable("speech command owner interrupted".into()))?
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wav::{SAMPLE_RATE, encode_wav, tone};

    #[tokio::test]
    async fn command_tts_synthesizes_wav_from_stdout() {
        let wav_path = std::env::temp_dir().join(format!("memoswish-cmd-tts-{}.wav", memoswish_core::ids::new_id()));
        let wav = encode_wav(&tone(440.0, 600, 0.4, SAMPLE_RATE), SAMPLE_RATE);
        std::fs::write(&wav_path, &wav).unwrap();

        let engine = CommandTts::new(CommandTtsConfig {
            external_transfer: false,
            id: "cat-tts".into(),
            program: "cat".into(),
            args: vec![wav_path.to_string_lossy().to_string()],
            text_via_stdin: false,
            default_voice: "en-us".into(),
            timeout_secs: 10,
        });
        let out = engine
            .synthesize(&TtsRequest {
                text: "Memoswish makes micro learning addictive.".into(),
                language: "en-US".into(),
                voice: "default".into(),
                speed: 1.0,
            })
            .await
            .unwrap();
        let _ = std::fs::remove_file(&wav_path);

        assert_eq!(out.duration_ms, 600);
        assert_eq!(out.words.len(), 5);
        assert!(out.words.windows(2).all(|w| w[0].end_ms <= w[1].start_ms));
    }

    #[tokio::test]
    #[ignore = "integration: requires espeak-ng on PATH"]
    async fn espeak_ng_synthesizes_when_installed() {
        let engine = CommandTts::espeak_ng();
        let out = engine
            .synthesize(&TtsRequest {
                text: "Hello from espeak".into(),
                language: "en-US".into(),
                voice: "en-us".into(),
                speed: 1.0,
            })
            .await
            .unwrap();
        assert!(out.duration_ms > 0);
        assert_eq!(out.words.len(), 3);
    }
}

#[cfg(test)]
mod failure_security_tests {
    use super::*;
    #[tokio::test]
    async fn spawn_failure_and_debug_hide_command_configuration() {
        let engine = CommandTts::new(CommandTtsConfig {
            external_transfer: true,
            id: "test".into(),
            program: "SECRET_SENTINEL-missing-executable".into(),
            args: vec!["SECRET_SENTINEL".into()],
            text_via_stdin: false,
            default_voice: "default".into(),
            timeout_secs: 30,
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
        assert!(!format!("{engine:?} {error:?} {error}").contains("SECRET_SENTINEL"));
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    #[test]
    fn command_privacy_defaults_external_and_preserves_explicit_local_engines() {
        let config: CommandTtsConfig = serde_json::from_value(serde_json::json!({"program":"remote-speech"})).unwrap();
        let external = CommandTts::new(config.clone());
        assert!(external.external_transfer());
        let local = CommandTts::new(CommandTtsConfig { external_transfer: false, ..config });
        assert!(!local.external_transfer());
        assert_ne!(external.cache_namespace(), local.cache_namespace());
        assert!(!CommandTts::espeak_ng().external_transfer());
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    #[tokio::test]
    async fn bounded_pipes_close_stdin_and_reject_oversized_output() {
        let input = vec![b'x'; 128 * 1024];
        let output = run_bounded("cat", &[], Some(&input), 2, input.len()).await.unwrap();
        assert_eq!(input, output);
        assert!(run_bounded("cat", &["/dev/zero".into()], None, 2, 1024).await.is_err());
        let error = run_bounded("SECRET_SENTINEL-missing", &[], None, 1, 1024).await.unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
    }
    #[tokio::test]
    async fn deadline_and_stderr_limit_reap_children_without_raw_output() {
        let timeout = run_bounded("sleep", &["30".into()], None, 0, 1024).await.unwrap_err();
        assert!(timeout.to_string().contains("timed out"));
        let stderr = run_bounded(
            "awk",
            &[r#"BEGIN { for (i=0; i<65537; i++) printf "x" > "/dev/stderr" }"#.into()],
            None,
            2,
            1024,
        )
        .await
        .unwrap_err();
        assert!(stderr.to_string().contains("limit"));
        for listing in [
            b"".as_slice(),
            b"SECRET_SENTINEL",
            b"Pty Language\nSECRET_SENTINEL",
            b"Pty Language\n5 /SECRET_SENTINEL M name file",
        ] {
            let error = CommandTts::parse_voice_listing(listing).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
        }
    }

    #[tokio::test]
    async fn diagnostics_never_run_generic_commands_or_expose_private_paths() {
        let config = CommandTtsConfig {
            external_transfer: false,
            id: "private".into(),
            program: "SECRET_SENTINEL".into(),
            args: vec![],
            text_via_stdin: true,
            default_voice: "SECRET_SENTINEL".into(),
            timeout_secs: 1,
        };
        let result = CommandTts::new(config).diagnostics().await;
        assert_eq!(result.state, memoswish_protocol::SpeechDiagnosticState::Unchecked);
        assert!(!serde_json::to_string(&result).unwrap().contains("SECRET_SENTINEL"));
    }
    #[tokio::test]
    #[ignore = "integration: requires espeak-ng on PATH"]
    async fn local_speech_languages_and_missing_voice_are_explicit() {
        let engine = CommandTts::espeak_ng();
        let diagnostics = engine.diagnostics().await;
        assert_eq!(diagnostics.state, memoswish_protocol::SpeechDiagnosticState::Available);
        for (text, language, voice) in
            [("A clear local learning sentence.", "en-US", "en-us"), ("每天学习一点新的知识。", "zh-CN", "cmn")]
        {
            let out = engine
                .synthesize(&TtsRequest {
                    text: text.into(),
                    language: language.into(),
                    voice: voice.into(),
                    speed: 1.0,
                })
                .await
                .unwrap();
            assert!(out.duration_ms > 100);
            assert_eq!(out.alignment_quality, Some(memoswish_protocol::AlignmentQuality::Estimated));
            assert_eq!(crate::wav::pcm_info(&out.audio).unwrap().channels, 1);
        }
        let mut argv = CommandTts::espeak_ng();
        argv.cfg.text_via_stdin = false;
        *argv.cfg.args.last_mut().unwrap() = "{text}".into();
        let literal = argv
            .synthesize(&TtsRequest {
                text: "-f/SECRET_SENTINEL-missing-file".into(),
                language: "en-US".into(),
                voice: "en-us".into(),
                speed: 1.0,
            })
            .await
            .unwrap();
        assert!(literal.duration_ms > 0);
        for (language, voice) in [("en-US", "MISSING_VOICE"), ("invalid-language", "default")] {
            assert!(
                engine
                    .synthesize(&TtsRequest {
                        text: "hello".into(),
                        language: language.into(),
                        voice: voice.into(),
                        speed: 1.0
                    })
                    .await
                    .is_err()
            );
        }
    }
}

#[cfg(all(test, unix))]
mod cancellation_budget_tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_command_retains_permit_until_child_is_killed_and_reaped() {
        let path = std::env::temp_dir().join(format!("p39-child-{}", memoswish_core::ids::new_id()));
        let output = path.clone();
        let waiter = tokio::spawn(async move {
            run_bounded(
                "sh",
                &[
                    "-c".into(),
                    "echo $$ > \"$1\"; exec sleep 30".into(),
                    "fixture".into(),
                    output.display().to_string(),
                ],
                None,
                1,
                1024,
            )
            .await
        });
        let pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(text) = tokio::fs::read_to_string(&path).await
                    && let Ok(pid) = text.trim().parse::<i32>()
                {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(super::super::EXECUTIONS.available_permits(), 3);
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        assert!(rustix::process::test_kill_process(pid).is_ok());
        tokio::time::timeout(Duration::from_secs(2), async {
            while super::super::EXECUTIONS.available_permits() != 4 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(rustix::process::test_kill_process(pid).is_err(), "owned child must be reaped");
        std::fs::remove_file(path).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn aborted_command_owner_terminates_same_group_descendants() {
        let path = std::env::temp_dir().join(format!("p39-group-{}", memoswish_core::ids::new_id()));
        let output = path.clone();
        let owner = tokio::spawn(async move {
            run_child(
                "sh",
                &[
                    "-c".into(),
                    "sleep 30 & echo $! > \"$1\"; wait".into(),
                    "fixture".into(),
                    output.display().to_string(),
                ],
                None,
                60,
                1024,
            )
            .await
        });
        let pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(text) = tokio::fs::read_to_string(&path).await
                    && let Ok(pid) = text.trim().parse::<i32>()
                {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        owner.abort();
        let _ = owner.await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match tokio::fs::read_to_string(format!("/proc/{pid}/stat")).await {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Ok(stat) if stat.rsplit_once(") ").is_some_and(|(_, fields)| fields.starts_with('Z')) => break,
                    _ => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("aborting the owner must stop descendants without waiting for their own timer");
        std::fs::remove_file(path).unwrap();
    }
}
