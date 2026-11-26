//! 严格编辑和来源输入的公共边界。
use crate::{CoreError, CoreResult};
use memoswish_protocol::*;
pub fn published(card: &Card) -> bool {
    card.content.as_ref().is_none_or(|m| m.publication == "published")
}
pub fn validate_sources(sources: &[String]) -> CoreResult<()> {
    if sources.len() > 8 {
        return Err(CoreError::invalid("at most 8 source references"));
    }
    for source in sources {
        let authority = source.strip_prefix("https://").unwrap_or("").split(['/', '?', '#']).next().unwrap_or("");
        let mut parts = authority.split(':');
        let host = parts.next().unwrap_or("");
        let port = parts.next();
        if host.is_empty()
            || host.starts_with('.')
            || host.ends_with('.')
            || host.split('.').any(|p| p.is_empty() || p.starts_with('-') || p.ends_with('-'))
            || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || parts.next().is_some()
            || port.is_some_and(|p| p.parse::<u16>().is_err() || p == "0")
            || source.len() > 2048
            || source.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\')
        {
            return Err(CoreError::invalid("source must be a safe HTTPS URL with a DNS or IPv4 host"));
        }
    }
    Ok(())
}
pub fn validate_save(save: &CardSave) -> CoreResult<()> {
    if save.card.id.is_some() && save.card.expected_revision.is_none() {
        return Err(CoreError::invalid("strict update requires expected_revision"));
    }
    if let Some(p) = &save.provenance {
        validate_provenance(p)?;
    }
    Ok(())
}
pub fn validate_provenance(p: &ContentProvenance) -> CoreResult<()> {
    if p.source_id_is_digest
        && !p.source_id.as_deref().is_some_and(|id| {
            id.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
    {
        return Err(CoreError::invalid("invalid source identity digest"));
    }
    if !["", "unknown", "manual", "import", "starter", "agent", "heuristic", "provider"].contains(&p.method.as_str())
        || serde_json::to_vec(p).map_err(CoreError::internal)?.len() > 16384
    {
        return Err(CoreError::invalid("invalid provenance or provenance exceeds 16 KiB"));
    }
    validate_sources(&p.sources)
}

pub fn validate_report(report: &ReportCreate) -> CoreResult<()> {
    if report.observed_revision == 0 || report.text.trim().is_empty() || report.text.len() > 2048 {
        return Err(CoreError::invalid("report requires a positive revision and 1..=2048 text bytes"));
    }
    validate_sources(&report.sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn references_reject_credentials_controls_and_unsafe_schemes() {
        for bad in [
            "http://example.org",
            "https://user:secret@example.org",
            "javascript:alert(1)",
            "https://example.org\\@evil.org",
            "https://example.org\n/secret",
            "https:///empty",
            "https://example.org:99999",
        ] {
            assert!(validate_sources(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(validate_sources(&["https://example.org/source?q=one#two".into()]).is_ok());
        assert!(validate_sources(&vec!["https://example.org".into(); 9]).is_err());
    }
}
