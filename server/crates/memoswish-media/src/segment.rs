//! 文本分词：为逐词时间戳提供 token 与 Unicode 标量区间。

/// 一个待朗读的 token。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// 展示文本（含紧随其后的标点）。
    pub text: String,
    /// 起始 Unicode 标量下标（含）。
    pub char_start: u32,
    /// 结束 Unicode 标量下标（不含）。
    pub char_end: u32,
    /// 是否以停顿型标点结尾（逗号、句号等），用于插入停顿。
    pub pause_after: bool,
}

/// 是否为“按字朗读”的 CJK 字符。
pub fn is_cjk(c: char) -> bool {
    matches!(c as u32,
        0x3040..=0x30FF   // 平假名、片假名
        | 0x3400..=0x4DBF // CJK 扩展 A
        | 0x4E00..=0x9FFF // CJK 统一表意文字
        | 0xAC00..=0xD7AF // 韩文音节
        | 0xF900..=0xFAFF // CJK 兼容表意文字
    )
}

/// 是否为标点（ASCII 或全角）。
pub fn is_punct(c: char) -> bool {
    c.is_ascii_punctuation() || "，。！？、；：“”‘’（）《》…—·「」".contains(c)
}

fn is_pause(c: char) -> bool {
    ",.!?;:，。！？；：、…".contains(c)
}

/// 分词。拉丁语按空白切分，CJK 逐字切分；标点并入前一个 token。
pub fn tokenize(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens: Vec<Token> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if is_punct(c) {
            // 标点并入前一个 token；若位于开头则跳过。
            if let Some(last) = tokens.last_mut()
                && last.char_end as usize == i
            {
                last.text.push(c);
                last.char_end += 1;
                last.pause_after |= is_pause(c);
            }
            i += 1;
            continue;
        }
        let start = i;
        if is_cjk(c) {
            i += 1;
        } else {
            while i < chars.len() && !chars[i].is_whitespace() && !is_cjk(chars[i]) && !is_punct(chars[i]) {
                i += 1;
            }
            // 保留词内撇号与连字符，例如 don't、well-known。
            while i + 1 < chars.len()
                && (chars[i] == '\'' || chars[i] == '-')
                && chars[i + 1].is_alphanumeric()
                && !is_cjk(chars[i + 1])
            {
                i += 1;
                while i < chars.len() && !chars[i].is_whitespace() && !is_cjk(chars[i]) && !is_punct(chars[i]) {
                    i += 1;
                }
            }
        }
        tokens.push(Token {
            text: chars[start..i].iter().collect(),
            char_start: start as u32,
            char_end: i as u32,
            pause_after: false,
        });
    }
    tokens
}

/// 去除轻量 Markdown 标记，得到适合朗读的纯文本。
pub fn strip_markdown(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '*' | '_' | '`' | '#' | '>')).collect::<String>().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin_tokens_with_punctuation() {
        let t = tokenize("Hello, world! don't stop well-known.");
        let texts: Vec<_> = t.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(texts, ["Hello,", "world!", "don't", "stop", "well-known."]);
        assert!(t[0].pause_after);
        assert!(!t[2].pause_after);
        assert_eq!((t[1].char_start, t[1].char_end), (7, 13));
    }

    #[test]
    fn cjk_tokens_per_char() {
        let t = tokenize("机缘巧合，Rust 很棒。");
        let texts: Vec<_> = t.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(texts, ["机", "缘", "巧", "合，", "Rust", "很", "棒。"]);
        assert_eq!((t[4].char_start, t[4].char_end), (5, 9));
    }
}
