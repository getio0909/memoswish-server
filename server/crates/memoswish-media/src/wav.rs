//! 最小 WAV（PCM 16-bit 单声道）编解码与音调合成工具。

/// 默认采样率。
pub(crate) static PROCESSING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

pub const SAMPLE_RATE: u32 = 22_050;

/// 把 [-1, 1] 浮点样本编码为 16-bit PCM 单声道 WAV。
pub fn encode_wav(samples: &[f32], sample_rate: u32) -> Vec<u8> {
    let data_len = (samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_len as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    // PCM 格式、单声道。
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&(sample_rate * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        let v = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// 严格 PCM 几何校验；在解码前拒绝不可信长度与不支持的格式。
pub fn pcm_info(bytes: &[u8]) -> memoswish_core::CoreResult<memoswish_protocol::PcmLoop> {
    use memoswish_core::CoreError;
    let invalid = || CoreError::invalid("unsupported or malformed PCM WAV");
    if bytes.len() < 44
        || bytes.len() > 10 * 1024 * 1024
        || &bytes[..4] != b"RIFF"
        || &bytes[8..12] != b"WAVE"
        || u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| invalid())?) as usize + 8 != bytes.len()
    {
        return Err(invalid());
    }
    let mut pos = 12usize;
    let mut format = None;
    let mut data = None;
    while pos < bytes.len() {
        memoswish_content::processing::checkpoint(8)?;
        let header = bytes.get(pos..pos + 8).ok_or_else(invalid)?;
        let size = u32::from_le_bytes(header[4..8].try_into().map_err(|_| invalid())?) as usize;
        let body = pos + 8;
        let end = body.checked_add(size).filter(|e| *e <= bytes.len()).ok_or_else(invalid)?;
        if &header[..4] == b"fmt " {
            if format.is_some() || ![16, 40].contains(&size) {
                return Err(invalid());
            }
            let f = &bytes[body..end];
            let u16_at = |i| u16::from_le_bytes([f[i], f[i + 1]]);
            let u32_at = |i| u32::from_le_bytes([f[i], f[i + 1], f[i + 2], f[i + 3]]);
            let (channels, rate, bits) = (u16_at(2), u32_at(4), u16_at(14));
            let pcm_format = if size == 16 {
                u16_at(0) == 1
            } else {
                u16_at(0) == 0xfffe
                    && u16_at(16) == 22
                    && u16_at(18) == bits
                    && (if channels == 1 { vec![0, 1, 4] } else { vec![0, 3] }).contains(&u32_at(20))
                    && f[24..40] == [1, 0, 0, 0, 0, 0, 16, 0, 128, 0, 0, 170, 0, 56, 155, 113]
            };
            if !pcm_format
                || !(1..=2).contains(&channels)
                || !(8000..=96000).contains(&rate)
                || ![8, 16, 24, 32].contains(&bits)
                || u16_at(12) != channels * (bits / 8)
                || u32_at(8) != rate * u32::from(channels) * u32::from(bits / 8)
            {
                return Err(invalid());
            }
            format = Some((channels, rate, bits));
        } else if &header[..4] == b"data" && (data.replace(size).is_some() || format.is_none()) {
            return Err(invalid());
        }
        pos = end.checked_add(size & 1).filter(|p| *p <= bytes.len()).ok_or_else(invalid)?;
    }
    let (channels, rate, bits) = format.ok_or_else(invalid)?;
    let data = data.ok_or_else(invalid)?;
    let block = usize::from(channels) * usize::from(bits / 8);
    if data == 0 || data % block != 0 {
        return Err(invalid());
    }
    let frames = (data / block) as u32;
    if frames > rate * 300 {
        return Err(invalid());
    }
    Ok(memoswish_protocol::PcmLoop {
        sample_rate: rate,
        channels,
        bits_per_sample: bits,
        frames,
        source_sha256: memoswish_core::ids::sha256_hex(bytes),
        source_start_frame: 0,
        source_end_frame: frames,
    })
}

/// 毫秒仅用于旧客户端显示，帧数才是裁切边界。
pub fn wav_duration_ms(bytes: &[u8]) -> Option<u32> {
    let info = pcm_info(bytes).ok()?;
    Some((u64::from(info.frames) * 1000 / u64::from(info.sample_rate)) as u32)
}

/// 只接受成功完成的已知 eSpeak stdout 流式头，不宽容上传文件。
pub fn normalize_espeak_stdout(mut bytes: Vec<u8>) -> memoswish_core::CoreResult<Vec<u8>> {
    if bytes.len() >= 44
        && &bytes[..4] == b"RIFF"
        && &bytes[8..20] == b"WAVEfmt \x10\x00\x00\x00"
        && &bytes[36..40] == b"data"
        && bytes[4..8] == 0x7ffff024u32.to_le_bytes()
        && bytes[40..44] == 0x7ffff000u32.to_le_bytes()
        && bytes.len() <= 10 * 1024 * 1024
    {
        let len = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&(len - 8).to_le_bytes());
        bytes[40..44].copy_from_slice(&(len - 44).to_le_bytes());
    }
    pcm_info(&bytes)?;
    Ok(bytes)
}

/// 整数样本无归一化地物化单个半开帧区间。
pub fn clip_pcm(
    bytes: &[u8],
    start: u32,
    end: u32,
) -> memoswish_core::CoreResult<(Vec<u8>, memoswish_protocol::PcmLoop)> {
    use memoswish_core::CoreError;
    let budget = memoswish_content::processing::WorkBudget::default();
    let mut info = pcm_info(bytes)?;
    if start >= end || end > info.frames {
        return Err(CoreError::invalid("invalid PCM frame range"));
    }
    let invalid = |_| CoreError::invalid("PCM WAV processing failed");
    let mut reader = hound::WavReader::new(std::io::Cursor::new(bytes)).map_err(invalid)?;
    reader.seek(start).map_err(|_| CoreError::invalid("PCM seek failed"))?;
    let mut output = std::io::Cursor::new(Vec::new());
    {
        let mut writer = hound::WavWriter::new(&mut output, reader.spec()).map_err(invalid)?;
        for (index, sample) in
            reader.samples::<i32>().take(((end - start) * u32::from(info.channels)) as usize).enumerate()
        {
            if index.is_multiple_of(4096) {
                budget.charge(4096)?;
            }
            writer.write_sample(sample.map_err(invalid)?).map_err(invalid)?;
        }
        writer.finalize().map_err(invalid)?;
    }
    let mut output = output.into_inner();
    if output.len() % 2 == 1 {
        output.push(0);
        let riff_size = output.len() as u32 - 8;
        output[4..8].copy_from_slice(&riff_size.to_le_bytes());
    }
    let actual = pcm_info(&output)?;
    if actual.frames != end - start {
        return Err(CoreError::invalid("PCM frame count mismatch"));
    }
    info.frames = end - start;
    info.source_start_frame = start;
    info.source_end_frame = end;
    Ok((output, info))
}

/// 生成带起落包络的正弦音调，避免爆音。
pub fn tone(freq: f32, ms: u32, amp: f32, sample_rate: u32) -> Vec<f32> {
    let n = (sample_rate as u64 * ms as u64 / 1000) as usize;
    let ramp = (sample_rate as usize / 100).max(1).min(n / 2).max(1);
    (0..n)
        .map(|i| {
            let t = i as f32 / sample_rate as f32;
            let env = if i < ramp {
                i as f32 / ramp as f32
            } else if i + ramp > n {
                (n - i) as f32 / ramp as f32
            } else {
                1.0
            };
            (2.0 * std::f32::consts::PI * freq * t).sin() * amp * env
        })
        .collect()
}

/// 生成静音。
pub fn silence(ms: u32, sample_rate: u32) -> Vec<f32> {
    vec![0.0; (sample_rate as u64 * ms as u64 / 1000) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wav_roundtrip_duration() {
        let mut s = tone(440.0, 1000, 0.5, SAMPLE_RATE);
        s.extend(silence(500, SAMPLE_RATE));
        let wav = encode_wav(&s, SAMPLE_RATE);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(wav_duration_ms(&wav), Some(1500));
        assert_eq!(wav_duration_ms(b"nope"), None);
    }
}

#[cfg(test)]
mod pcm_tests {
    use super::*;
    fn fixture(bits: u16, channels: u16, frames: u32) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut writer = hound::WavWriter::new(
                &mut out,
                hound::WavSpec {
                    channels,
                    sample_rate: 8000,
                    bits_per_sample: bits,
                    sample_format: hound::SampleFormat::Int,
                },
            )
            .unwrap();
            for i in 0..frames * u32::from(channels) {
                writer.write_sample((i as i32 % 63) - 31).unwrap();
            }
            writer.finalize().unwrap();
        }
        let mut bytes = out.into_inner();
        if bytes.len() % 2 == 1 {
            bytes.push(0);
            let n = bytes.len() as u32 - 8;
            bytes[4..8].copy_from_slice(&n.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn all_integer_widths_and_channels_keep_exact_samples_and_end_boundary() {
        for bits in [8, 16, 24, 32] {
            for channels in [1, 2] {
                let bytes = fixture(bits, channels, 5);
                for (start, end) in [(0, 5), (1, 4), (4, 5)] {
                    let (clipped, info) = clip_pcm(&bytes, start, end)
                        .unwrap_or_else(|e| panic!("bits={bits} channels={channels} start={start} end={end}: {e}"));
                    assert_eq!(info.frames, end - start);
                    assert_eq!(info.channels, channels);
                    assert_eq!((info.source_start_frame, info.source_end_frame), (start, end));
                    assert_eq!(info.source_sha256, memoswish_core::ids::sha256_hex(&bytes));
                    let actual: Vec<i32> = hound::WavReader::new(std::io::Cursor::new(&clipped))
                        .unwrap()
                        .samples::<i32>()
                        .map(Result::unwrap)
                        .collect();
                    let expected: Vec<i32> =
                        (start * u32::from(channels)..end * u32::from(channels)).map(|i| i as i32 - 31).collect();
                    assert_eq!(actual, expected);
                    assert_eq!(clipped, clip_pcm(&bytes, start, end).unwrap().0);
                }
                for (start, end) in [(0, 0), (3, 2), (0, 6), (u32::MAX, u32::MAX)] {
                    assert!(clip_pcm(&bytes, start, end).is_err());
                }
            }
        }
    }
    #[test]
    fn pcm32_extremes_and_values_beyond_float_precision_remain_exact() {
        let values = [i32::MIN, i32::MAX, 16_777_217, -16_777_217];
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut writer = hound::WavWriter::new(
                &mut buffer,
                hound::WavSpec {
                    channels: 2,
                    sample_rate: 8000,
                    bits_per_sample: 32,
                    sample_format: hound::SampleFormat::Int,
                },
            )
            .unwrap();
            for value in values {
                writer.write_sample(value).unwrap();
            }
            writer.finalize().unwrap();
        }
        let (bytes, _) = clip_pcm(&buffer.into_inner(), 0, 2).unwrap();
        let samples: Vec<i32> =
            hound::WavReader::new(std::io::Cursor::new(bytes)).unwrap().samples::<i32>().map(Result::unwrap).collect();
        assert_eq!(samples, values);
    }

    #[test]
    fn malformed_lengths_formats_rates_and_streaming_uploads_fail_closed() {
        let valid = fixture(16, 2, 16);
        for offset in [0, 4, 8, 16, 20, 22, 24, 28, 32, 34, 40] {
            let mut bytes = valid.clone();
            bytes[offset] ^= 0xff;
            assert!(pcm_info(&bytes).is_err(), "offset {offset}");
        }
        assert!(pcm_info(&valid[..valid.len() - 1]).is_err());
        assert!(pcm_info(&vec![0; 10 * 1024 * 1024 + 1]).is_err());
        let mut streaming = fixture(16, 1, 16);
        streaming[4..8].copy_from_slice(&0x7ffff024u32.to_le_bytes());
        streaming[40..44].copy_from_slice(&0x7ffff000u32.to_le_bytes());
        assert!(pcm_info(&streaming).is_err());
        let normalized = normalize_espeak_stdout(streaming).unwrap();
        assert_eq!(pcm_info(&normalized).unwrap().frames, 16);
        let mut float = fixture(16, 1, 16);
        float[20..22].copy_from_slice(&3u16.to_le_bytes());
        assert!(pcm_info(&float).is_err());
    }
}

#[cfg(test)]
mod processing_envelope_tests {
    use super::*;
    fn pcm8(frames: u32, rate: u32, channels: u16) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut writer = hound::WavWriter::new(
                &mut out,
                hound::WavSpec {
                    channels,
                    sample_rate: rate,
                    bits_per_sample: 8,
                    sample_format: hound::SampleFormat::Int,
                },
            )
            .unwrap();
            for _ in 0..frames * u32::from(channels) {
                writer.write_sample(0i8).unwrap();
            }
            writer.finalize().unwrap();
        }
        let mut bytes = out.into_inner();
        if bytes.len() % 2 == 1 {
            bytes.push(0);
            let size = bytes.len() as u32 - 8;
            bytes[4..8].copy_from_slice(&size.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn pcm_duration_rate_channel_boundaries_plus_one() {
        assert!(pcm_info(&pcm8(8000 * 300, 8000, 1)).is_ok());
        assert!(pcm_info(&pcm8(8000 * 300 + 1, 8000, 1)).is_err());
        assert!(pcm_info(&pcm8(8, 96000, 2)).is_ok());
        assert!(pcm_info(&pcm8(8, 96001, 2)).is_err());
        assert!(pcm_info(&pcm8(8, 96000, 3)).is_err());
        assert!(pcm_info(&pcm8(8, 7999, 1)).is_err());
    }
}
