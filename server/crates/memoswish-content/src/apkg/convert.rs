//! 将受限模板、Cloze 与惰性 HTML 转为已有内容块。

use std::collections::{BTreeMap, BTreeSet};

use memoswish_core::ids::sha256_hex;
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::{AssetRef, CardFace, ContentBlock};
use scraper::{ElementRef, Html, Node};

use super::collection::{Model, Note};
use super::{ApkgLimits, MediaUpload, Warnings};

#[derive(Default)]
pub struct Converter {
    pub media: BTreeMap<String, Vec<u8>>,
    pub uploads: BTreeMap<String, MediaUpload>,
    pub warnings: Warnings,
    pub audio: BTreeSet<String>,
    pub prefix: String,
    pub resolved: BTreeMap<String, AssetRef>,
    #[cfg(test)]
    pub media_hashes: BTreeMap<String, usize>,
}

pub fn render(template: &str, model: &Model, note: &Note, front: &str, active: u32, back: bool) -> CoreResult<String> {
    let mut output = String::new();
    let mut rest = template;
    let mut active_found = false;
    let mut has_cloze = false;
    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let end = rest.find("}}").ok_or_else(|| CoreError::invalid("unclosed Anki template replacement"))?;
        let token = rest[..end].trim();
        if token == "FrontSide" {
            output.push_str(front);
        } else {
            let (is_cloze, name) = token.strip_prefix("cloze:").map_or((false, token), |n| (true, n));
            let field = model.flds.iter().find(|f| f.name == name).ok_or_else(|| {
                CoreError::invalid(format!("unsupported template token `{token}` in note type `{}`", model.name))
            })?;
            let value = &note.fields[field.ord];
            if is_cloze {
                if model.kind != 1 {
                    return Err(CoreError::invalid("cloze filter requires a Cloze note type"));
                }
                let (text, found) = cloze(value, active, back, 0)?;
                active_found |= found;
                has_cloze = true;
                output.push_str(&text);
            } else {
                output.push_str(value);
            }
        }
        if output.len() > ApkgLimits::RENDERED_FACE {
            return Err(CoreError::invalid("rendered Anki template exceeds 1 MiB"));
        }
        rest = &rest[end + 2..];
    }
    output.push_str(rest);
    if output.len() > ApkgLimits::RENDERED_FACE {
        return Err(CoreError::invalid("rendered Anki template exceeds 1 MiB"));
    }
    if model.kind == 1 && (!has_cloze || !active_found) {
        return Err(CoreError::invalid("Cloze card ordinal has no matching deletion"));
    }
    Ok(output)
}

pub(super) fn cloze(input: &str, active: u32, back: bool, depth: usize) -> CoreResult<(String, bool)> {
    cloze_with_math(input, active, back, depth, MathJaxState::default())
}

#[derive(Clone, Copy, Default)]
struct MathJaxState {
    current: Option<(u8, usize)>,
    next_id: usize,
}

impl MathJaxState {
    fn region(self) -> Option<usize> {
        self.current.map(|(_, id)| id)
    }

    fn advance(&mut self, input: &[u8], offset: usize, last_closes: [Option<usize>; 2]) -> usize {
        let Some(&[b'\\', delimiter]) = input.get(offset..offset + 2) else {
            return 1;
        };
        if let Some((close, _)) = self.current {
            if delimiter == close {
                self.current = None;
                return 2;
            }
        } else {
            let (close, last) = match delimiter {
                b'(' => (b')', last_closes[0]),
                b'[' => (b']', last_closes[1]),
                _ => return 1,
            };
            // 未闭合的公式分隔符作为正文，不能吞掉删除标记的结尾。
            // 预先查找最后一个结尾，避免对大量未闭合开头反复扫描全文。
            if last.is_some_and(|last| last >= offset + 2) {
                self.current = Some((close, self.next_id));
                self.next_id += 1;
                return 2;
            }
        }
        1
    }
}

fn cloze_with_math(
    input: &str,
    active: u32,
    back: bool,
    depth: usize,
    mut math: MathJaxState,
) -> CoreResult<(String, bool)> {
    crate::processing::checkpoint(input.len())?;
    if input.len() > ApkgLimits::FIELD || depth > 16 {
        return Err(CoreError::invalid("Cloze nesting exceeds 16 levels"));
    }
    let bytes = input.as_bytes();
    let last_closes = [input.rfind(r"\)"), input.rfind(r"\]")];
    let mut output = String::new();
    let mut cursor = 0;
    let mut found = false;
    while let Some(start) = input[cursor..].find("{{c").map(|start| cursor + start) {
        crate::processing::checkpoint(1)?;
        output.push_str(&input[cursor..start]);
        while cursor < start {
            cursor += math.advance(bytes, cursor, last_closes);
        }
        let initial_math = math;
        let rest = &input[start + 3..];
        let separator = rest.find("::").ok_or_else(|| CoreError::invalid("malformed Cloze index"))?;
        let numbers = &rest[..separator];
        let mut matching = false;
        for n in numbers.split(',') {
            let n: u32 = n.parse().map_err(|_| CoreError::invalid("invalid Cloze index"))?;
            if n == 0 {
                return Err(CoreError::invalid("Cloze indices start at 1"));
            }
            matching |= n == active;
        }
        let body_start = start + 3 + separator + 2;
        let mut regions = vec![math.region()];
        let mut end = None;
        let mut hint = None;
        let mut i = body_start;
        while i + 1 < bytes.len() {
            if i.is_multiple_of(4096) {
                crate::processing::checkpoint(0)?;
            }
            if bytes[i..].starts_with(b"{{c") {
                regions.push(math.region());
                if depth + regions.len() > 16 {
                    return Err(CoreError::invalid("Cloze nesting exceeds 16 levels"));
                }
                i += 3;
            } else if &bytes[i..i + 2] == b"}}" && (math.region().is_none() || regions.last() == Some(&math.region())) {
                regions.pop();
                if regions.is_empty() {
                    end = Some(i);
                    break;
                }
                i += 2;
            } else if &bytes[i..i + 2] == b"::" && regions.len() == 1 && hint.is_none() {
                hint = Some(i);
                i += 2;
            } else {
                i += math.advance(bytes, i, last_closes);
            }
        }
        let end = end.ok_or_else(|| CoreError::invalid("unclosed Cloze deletion"))?;
        let answer_end = hint.unwrap_or(end);
        let (answer, nested) = cloze_with_math(&input[body_start..answer_end], active, back, depth + 1, initial_math)?;
        found |= matching || nested;
        if matching && !back {
            let hint = hint.map(|h| &input[h + 2..end]).unwrap_or("...");
            output.push('[');
            output.push_str(hint);
            output.push(']');
        } else {
            output.push_str(&answer);
        }
        cursor = end + 2;
    }
    output.push_str(&input[cursor..]);
    Ok((output, found))
}

#[derive(Clone, Copy)]
enum TagState {
    Name,
    BeforeAttribute,
    Attribute,
    AfterAttribute,
    BeforeValue,
    Value,
    QuotedValue(u8),
}

// 单次字节扫描先于 html5ever，限制其属性去重、格式重建和建树的输入规模。
// 保守拒绝标签内部的小于号，防止畸形标签或引号隐藏后续标签及属性。
pub(super) fn check_html_budget(html: &str) -> CoreResult<()> {
    let invalid = || CoreError::invalid("Anki HTML exceeds pre-parse byte, markup or attribute budget");
    if html.len() > ApkgLimits::HTML_FACE {
        return Err(invalid());
    }
    let mut state = None;
    let (mut markers, mut tag_bytes, mut total_bytes) = (0, 0, 0);
    let (mut names, mut equals, mut total_names, mut total_equals) = (0, 0, 0, 0);
    let bytes = html.as_bytes();
    for (offset, &byte) in bytes.iter().enumerate() {
        if byte == b'<' {
            markers += 1;
            if state.is_some() || markers > ApkgLimits::HTML_MARKERS {
                return Err(invalid());
            }
            // HTML 的标签开头只接受 ASCII 字母、斜杠、感叹号或问号。
            // 普通比较符仍计入原始小于号预算，但不会吞掉后续正文。
            if bytes
                .get(offset + 1)
                .is_some_and(|next| next.is_ascii_alphabetic() || matches!(next, b'/' | b'!' | b'?'))
            {
                state = Some(TagState::Name);
                tag_bytes = 0;
                names = 0;
                equals = 0;
            }
        }
        let Some(current) = state else { continue };
        tag_bytes += 1;
        total_bytes += 1;
        if tag_bytes > ApkgLimits::HTML_TAG || total_bytes > ApkgLimits::HTML_TAG_BYTES {
            return Err(invalid());
        }
        // HTML 仅在等号后的值开头识别引号；属性名和无引号值中的引号不是分隔符。
        if let TagState::QuotedValue(quote) = current {
            if byte == quote {
                state = Some(TagState::BeforeAttribute);
            }
            continue;
        }
        if byte == b'>' {
            state = None;
            continue;
        }
        let space = matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c);
        let attribute_start = matches!(current, TagState::BeforeAttribute | TagState::AfterAttribute)
            && !space
            && byte != b'/'
            && !(matches!(current, TagState::AfterAttribute) && byte == b'=');
        if attribute_start {
            names += 1;
            total_names += 1;
        }
        if byte == b'=' {
            equals += 1;
            total_equals += 1;
        }
        if names > ApkgLimits::HTML_TAG_ATTRIBUTES
            || equals > ApkgLimits::HTML_TAG_ATTRIBUTES
            || total_names > ApkgLimits::HTML_ATTRIBUTES
            || total_equals > ApkgLimits::HTML_ATTRIBUTES
        {
            return Err(invalid());
        }
        state = Some(match current {
            TagState::Name | TagState::Attribute | TagState::AfterAttribute if byte == b'/' => {
                TagState::BeforeAttribute
            }
            TagState::Name if space => TagState::BeforeAttribute,
            TagState::BeforeAttribute | TagState::AfterAttribute if attribute_start => TagState::Attribute,
            TagState::Attribute if space => TagState::AfterAttribute,
            TagState::Attribute | TagState::AfterAttribute if byte == b'=' => TagState::BeforeValue,
            TagState::BeforeValue if matches!(byte, b'\'' | b'"') => TagState::QuotedValue(byte),
            TagState::BeforeValue if !space => TagState::Value,
            TagState::Value if space => TagState::BeforeAttribute,
            _ => current,
        });
    }
    Ok(())
}

impl Converter {
    pub fn face(&mut self, html: &str, fallback: &str, question: bool) -> CoreResult<CardFace> {
        check_html_budget(html)?;
        let fragment = Html::parse_fragment(html);
        let mut stack = vec![(fragment.tree.root(), 0usize, false)];
        let mut count = 0;
        let mut text = String::new();
        let mut blocks = Vec::new();
        while let Some((node, depth, closing)) = stack.pop() {
            count += 1;
            if count > 40_000 || depth > 64 {
                return Err(CoreError::invalid("Anki HTML exceeds node or nesting budget"));
            }
            match node.value() {
                Node::Text(value) => text.push_str(value),
                Node::Element(element) => {
                    let tag = element.name();
                    if matches!(
                        tag,
                        "script"
                            | "style"
                            | "iframe"
                            | "object"
                            | "embed"
                            | "svg"
                            | "math"
                            | "template"
                            | "audio"
                            | "video"
                    ) {
                        if matches!(tag, "audio" | "video") {
                            self.warnings.push("Embedded audio/video was omitted.");
                        }
                        continue;
                    }
                    if tag == "img" {
                        self.flush_text(&mut text, &mut blocks)?;
                        let src = element.attr("src").unwrap_or("");
                        let alt = element.attr("alt").unwrap_or("");
                        blocks.push(self.image(src, alt)?);
                        continue;
                    }
                    if tag == "table" && !closing {
                        self.flush_text(&mut text, &mut blocks)?;
                        if let Some(table) = table_block(ElementRef::wrap(node).unwrap(), depth, &mut count)? {
                            blocks.push(table);
                            continue;
                        }
                        self.warnings.push("HTML table layout was flattened with explicit cell separators.");
                    }
                    if matches!(tag, "td" | "th")
                        && !closing
                        && node
                            .prev_siblings()
                            .filter_map(ElementRef::wrap)
                            .any(|s| matches!(s.value().name(), "td" | "th"))
                    {
                        text.push_str(" | ");
                    }
                    if matches!(tag, "br" | "p" | "div" | "hr" | "li" | "tr" | "table" | "h1" | "h2" | "h3" | "pre") {
                        text.push('\n');
                    }
                    if closing {
                        continue;
                    }
                    stack.push((node, depth, true));
                }
                _ => {}
            }
            if !closing {
                for child in node.children().rev() {
                    stack.push((child, depth + 1, false));
                }
            }
        }
        self.flush_text(&mut text, &mut blocks)?;
        if question && blocks.is_empty() {
            return Err(CoreError::invalid("Anki question has no usable content after removing HTML/audio"));
        }
        if blocks.len() > 32 {
            return Err(CoreError::invalid("converted Anki face exceeds 32 blocks"));
        }
        let title = if question {
            let text = blocks.iter().filter_map(ContentBlock::speakable_text).collect::<Vec<_>>().join(" ");
            let mut chars = text.chars();
            let mut plain = String::new();
            while let Some(c) = chars.next() {
                plain.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
            }
            let title: String = plain.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(200).collect();
            if title.is_empty() { fallback.to_string() } else { title }
        } else {
            String::new()
        };
        Ok(CardFace { title, subtitle: None, blocks })
    }

    fn flush_text(&mut self, buffer: &mut String, blocks: &mut Vec<ContentBlock>) -> CoreResult<()> {
        let input = std::mem::take(buffer);
        let mut plain = String::new();
        let mut rest = input.as_str();
        while let Some(start) = rest.find("[sound:") {
            plain.push_str(&rest[..start]);
            let Some(end) = rest[start..].find(']') else {
                self.warnings.push("Malformed audio marker was preserved as text.");
                plain.push_str(&rest[start..]);
                rest = "";
                break;
            };
            let name = &rest[start + 7..start + end];
            if self.audio.insert(name.to_string()) {
                self.warnings.push(format!(
                    "Audio \"{name}\" was omitted because imported Anki audio playback is not supported."
                ));
            }
            rest = &rest[start + end + 1..];
        }
        plain.push_str(rest);
        math_blocks(&plain, blocks, &mut self.warnings)
    }

    fn image(&mut self, src: &str, alt: &str) -> CoreResult<ContentBlock> {
        let decoded = percent_encoding::percent_decode_str(src).decode_utf8().ok();
        let external = src.starts_with('/') || src.contains(':');
        let direct = if external { None } else { self.media.get_key_value(src) };
        let encoded = decoded.as_deref().filter(|s| !external && *s != src).and_then(|s| self.media.get_key_value(s));
        if direct.is_some() && encoded.is_some() {
            return Err(CoreError::invalid("ambiguous encoded image filename"));
        }
        let Some((name, bytes)) = direct.or(encoded) else {
            self.warnings.push(format!("Image \"{src}\" is missing or external and was omitted."));
            return Ok(ContentBlock::text(escape_markdown(&format!("[Missing image: {src}]"))));
        };
        if let Some(asset) = self.resolved.get(name) {
            return Ok(ContentBlock::Image { asset: asset.clone(), alt: alt.chars().take(200).collect() });
        }
        let (ext, mime) = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            ("png", "image/png")
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            ("jpg", "image/jpeg")
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            ("gif", "image/gif")
        } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            ("webp", "image/webp")
        } else {
            self.warnings.push(format!("Image \"{src}\" has an unsupported raster signature and was omitted."));
            return Ok(ContentBlock::text("[Unsupported image]"));
        };
        #[cfg(test)]
        {
            *self.media_hashes.entry(name.clone()).or_default() += 1;
        }
        let hash = sha256_hex(bytes);
        let key = format!("{}{hash}.{ext}", self.prefix);
        let asset = AssetRef {
            key: key.clone(),
            url: String::new(),
            mime: mime.into(),
            bytes: bytes.len() as u64,
            sha256: hash,
        };
        self.uploads.entry(key).or_insert_with(|| MediaUpload { asset: asset.clone(), bytes: bytes.clone() });
        self.resolved.insert(name.clone(), asset.clone());
        Ok(ContentBlock::Image { asset, alt: alt.chars().take(200).collect() })
    }
}

// 规则文本表格使用现有 Table，富内容、合并单元格和不等宽行交回普通遍历。
// 成功消费子树时计入同一节点/深度预算，避免表格绕过遍历限制。
fn table_block(table: ElementRef<'_>, depth: usize, count: &mut usize) -> CoreResult<Option<ContentBlock>> {
    let mut stack: Vec<_> = table.children().rev().map(|node| (node, depth + 1, false)).collect();
    let mut visits = *count + 1;
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut cell: Option<String> = None;
    let mut chars = 0;
    while let Some((node, depth, closing)) = stack.pop() {
        visits += 1;
        if visits > 40_000 || depth > 64 {
            return Err(CoreError::invalid("Anki HTML exceeds node or nesting budget"));
        }
        match node.value() {
            Node::Text(value) => {
                if let Some(cell) = &mut cell {
                    cell.push_str(value);
                } else if !value.trim().is_empty() {
                    return Ok(None);
                }
            }
            Node::Element(element) => {
                match element.name() {
                    "thead" | "tbody" | "tfoot" => {}
                    "tr" if !closing => {
                        rows.push(Vec::new());
                        if rows.len() > 101 {
                            return Err(CoreError::invalid("Anki table exceeds 100 data rows"));
                        }
                    }
                    "tr" => {}
                    "td" | "th" => {
                        if closing {
                            let value = cell.take().unwrap_or_default().trim().to_string();
                            // Table 单元格是纯文本，特殊块继续走现有图片、音频与公式转换。
                            if ["[sound:", r"\(", r"\[", "[$]", "[$$]", "[latex]"].iter().any(|s| value.contains(s)) {
                                return Ok(None);
                            }
                            chars += value.chars().count();
                            if chars > 8000 {
                                return Err(CoreError::invalid("Anki table exceeds 8000 characters"));
                            }
                            let Some(row) = rows.last_mut() else { return Ok(None) };
                            row.push(value);
                            if row.len() > 20 {
                                return Err(CoreError::invalid("Anki table exceeds 20 columns"));
                            }
                        } else {
                            if ["colspan", "rowspan"].iter().any(|name| element.attr(name).is_some_and(|v| v != "1")) {
                                return Ok(None);
                            }
                            cell = Some(String::new());
                        }
                    }
                    "br" if closing => {}
                    "br" | "p" | "div" | "li" => {
                        let Some(cell) = &mut cell else { return Ok(None) };
                        cell.push('\n');
                    }
                    "span" | "b" | "i" | "u" | "em" | "strong" | "s" | "sub" | "sup" | "small" | "a" | "code"
                        if cell.is_some() => {}
                    _ => return Ok(None),
                }
                if !closing {
                    stack.push((node, depth, true));
                }
            }
            _ => {}
        }
        if !closing {
            stack.extend(node.children().rev().map(|child| (child, depth + 1, false)));
        }
    }
    if rows.is_empty() || rows[0].is_empty() || rows.iter().any(|row| row.len() != rows[0].len()) {
        return Ok(None);
    }
    // 明确的 th 表头和没有 th 时的首行都映射到协议的 header。
    let header = rows.remove(0);
    *count = visits;
    Ok(Some(ContentBlock::Table { header, rows }))
}

fn escape_markdown(text: &str) -> String {
    let mut output = String::new();
    for c in text.chars() {
        if "\\`*_{}[]<>()#!|~".contains(c) {
            output.push('\\');
        }
        output.push(c);
    }
    output
}

fn push_text(text: &str, blocks: &mut Vec<ContentBlock>) {
    let mut chunk = String::new();
    let mut chars = 0usize;
    for c in text.trim().chars() {
        let escaped = "\\`*_{}[]<>()#!|~".contains(c);
        let width = if escaped { 2 } else { 1 };
        if chars + width > 8000 {
            blocks.push(ContentBlock::text(std::mem::take(&mut chunk)));
            chars = 0;
        }
        if escaped {
            chunk.push('\\');
        }
        chunk.push(c);
        chars += width;
    }
    if !chunk.is_empty() {
        blocks.push(ContentBlock::text(chunk));
    }
}

fn math_blocks(input: &str, blocks: &mut Vec<ContentBlock>, warnings: &mut Warnings) -> CoreResult<()> {
    let pairs = [
        ("\\(", "\\)", false),
        ("\\[", "\\]", true),
        ("[$$]", "[/$$]", true),
        ("[$]", "[/$]", false),
        ("[latex]", "[/latex]", true),
    ];
    let mut rest = input;
    while let Some((start, (open, close, display))) =
        pairs.iter().filter_map(|p| rest.find(p.0).map(|i| (i, p))).min_by_key(|p| p.0)
    {
        push_text(&rest[..start], blocks);
        let body = &rest[start + open.len()..];
        let Some(end) = body.find(close) else {
            warnings.push("Unmatched math delimiter was preserved as text.");
            push_text(&rest[start..], blocks);
            return Ok(());
        };
        let mut latex = body[..end].trim();
        if *open == "[latex]" {
            for (a, b) in [
                ("\\begin{displaymath}", "\\end{displaymath}"),
                ("\\begin{math}", "\\end{math}"),
                ("$$", "$$"),
                ("$", "$"),
            ] {
                if let Some(inner) = latex.strip_prefix(a).and_then(|s| s.strip_suffix(b)) {
                    latex = inner.trim();
                    break;
                }
            }
        }
        if latex.is_empty() || latex.chars().count() > 8000 {
            return Err(CoreError::invalid("Anki math block must contain 1 to 8000 characters"));
        }
        if *open == "[latex]"
            && (latex.contains("\\documentclass")
                || latex.contains("\\usepackage")
                || latex.contains("\\begin{document}"))
        {
            warnings.push("General LaTeX was preserved as code; imported TeX is never compiled.");
            blocks.push(ContentBlock::Code { language: "latex".into(), source: latex.into(), highlight_lines: vec![] });
        } else {
            blocks.push(ContentBlock::Math { latex: latex.into(), display: *display });
        }
        rest = &body[end + close.len()..];
    }
    push_text(rest, blocks);
    Ok(())
}
