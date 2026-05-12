use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: SecretKind,
    pub span: ByteSpan,
    pub confidence: Confidence,
    pub source: DetectorSource,
    pub original: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretKind {
    BearerToken,
    Jwt,
    CookieValue,
    OpenAiKey,
    AwsAccessKey,
    GithubToken,
    StripeKey,
    EnvValue,
    UrlQuerySecret,
    HighEntropyToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorSource {
    HeaderDetector,
    CookieDetector,
    EnvDetector,
    UrlQueryDetector,
    KnownSecretDetector,
    JwtDetector,
    EntropyDetector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingEntry {
    pub placeholder: String,
    pub original: String,
    pub kind: SecretKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MappingStore {
    pub version: u8,
    pub entries: Vec<MappingEntry>,
}

#[derive(Debug, Clone)]
pub struct ScrubOptions {
    pub preview: bool,
    pub strict: bool,
}

impl Default for ScrubOptions {
    fn default() -> Self {
        Self {
            preview: false,
            strict: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScrubResult {
    pub output: String,
    pub findings: Vec<Finding>,
    pub mappings: Vec<MappingEntry>,
}

impl ScrubResult {
    pub fn mapping_store(&self) -> MappingStore {
        MappingStore {
            version: 1,
            entries: self.mappings.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SafePromptError {
    #[error("invalid mapping store version: {0}")]
    InvalidMappingVersion(u8),
}

pub fn scrub(input: &str, options: ScrubOptions) -> Result<ScrubResult, SafePromptError> {
    let findings = plan_findings(detect_all(input), options.strict);
    let mut allocator = PlaceholderAllocator::default();
    let redactions = findings
        .iter()
        .cloned()
        .map(|finding| {
            let placeholder = allocator.placeholder_for(&finding);
            Redaction {
                finding,
                placeholder,
            }
        })
        .collect::<Vec<_>>();

    let mappings = allocator.entries;
    let output = if options.preview {
        render_preview(input, &redactions)
    } else {
        redact(input, &redactions)
    };

    Ok(ScrubResult {
        output,
        findings,
        mappings,
    })
}

pub fn restore(input: &str, mapping: &MappingStore) -> Result<String, SafePromptError> {
    if mapping.version != 0 && mapping.version != 1 {
        return Err(SafePromptError::InvalidMappingVersion(mapping.version));
    }

    let mut output = input.to_owned();
    for entry in &mapping.entries {
        output = output.replace(&entry.placeholder, &entry.original);
    }
    Ok(output)
}

#[derive(Debug, Clone)]
struct Redaction {
    finding: Finding,
    placeholder: String,
}

#[derive(Default)]
struct PlaceholderAllocator {
    seen: HashMap<String, String>,
    counts: HashMap<SecretKind, usize>,
    entries: Vec<MappingEntry>,
}

impl PlaceholderAllocator {
    fn placeholder_for(&mut self, finding: &Finding) -> String {
        if let Some(existing) = self.seen.get(&finding.original) {
            return existing.clone();
        }

        let count = self.counts.entry(finding.kind).or_insert(0);
        *count += 1;
        let placeholder = format!("[{}_{}]", finding.kind.placeholder_prefix(), count);

        self.seen
            .insert(finding.original.clone(), placeholder.clone());
        self.entries.push(MappingEntry {
            placeholder: placeholder.clone(),
            original: finding.original.clone(),
            kind: finding.kind,
        });
        placeholder
    }
}

impl SecretKind {
    fn placeholder_prefix(self) -> &'static str {
        match self {
            SecretKind::BearerToken => "BEARER_TOKEN",
            SecretKind::Jwt => "JWT",
            SecretKind::CookieValue => "COOKIE",
            SecretKind::OpenAiKey => "OPENAI_KEY",
            SecretKind::AwsAccessKey => "AWS_KEY",
            SecretKind::GithubToken => "GITHUB_TOKEN",
            SecretKind::StripeKey => "STRIPE_KEY",
            SecretKind::EnvValue => "ENV_SECRET",
            SecretKind::UrlQuerySecret => "URL_TOKEN",
            SecretKind::HighEntropyToken => "HIGH_ENTROPY",
        }
    }
}

fn detect_all(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_bearer(input));
    findings.extend(detect_cookie_values(input));
    findings.extend(detect_env_values(input));
    findings.extend(detect_url_query_secrets(input));
    findings.extend(detect_known_secrets(input));
    findings.extend(detect_jwt(input));
    findings.extend(detect_entropy_context(input));
    findings
}

fn plan_findings(mut findings: Vec<Finding>, strict: bool) -> Vec<Finding> {
    findings.retain(|finding| {
        finding.confidence == Confidence::High
            || (strict && finding.confidence == Confidence::Medium)
    });
    findings.sort_by(|a, b| {
        a.span
            .start
            .cmp(&b.span.start)
            .then_with(|| priority(b).cmp(&priority(a)))
            .then_with(|| span_len(b).cmp(&span_len(a)))
    });

    let mut planned: Vec<Finding> = Vec::new();
    'outer: for finding in findings {
        for existing in &planned {
            if overlaps(finding.span, existing.span) {
                continue 'outer;
            }
        }
        planned.push(finding);
    }
    planned.sort_by_key(|finding| finding.span.start);
    planned
}

fn priority(finding: &Finding) -> usize {
    match finding.source {
        DetectorSource::HeaderDetector
        | DetectorSource::CookieDetector
        | DetectorSource::UrlQueryDetector => 4,
        DetectorSource::KnownSecretDetector | DetectorSource::JwtDetector => 3,
        DetectorSource::EnvDetector => 2,
        DetectorSource::EntropyDetector => 1,
    }
}

fn span_len(finding: &Finding) -> usize {
    finding.span.end - finding.span.start
}

fn overlaps(a: ByteSpan, b: ByteSpan) -> bool {
    a.start < b.end && b.start < a.end
}

fn redact(input: &str, redactions: &[Redaction]) -> String {
    let mut output = input.to_owned();
    for redaction in redactions.iter().rev() {
        output.replace_range(
            redaction.finding.span.start..redaction.finding.span.end,
            &redaction.placeholder,
        );
    }
    output
}

fn render_preview(input: &str, redactions: &[Redaction]) -> String {
    redactions
        .iter()
        .map(|redaction| {
            let (line, col) = line_col(input, redaction.finding.span.start);
            format!(
                "WOULD_REDACT  {:?}  {:?}  line {} col {}  -> {}",
                redaction.finding.confidence,
                redaction.finding.kind,
                line,
                col,
                redaction.placeholder
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn line_col(input: &str, byte_pos: usize) -> (usize, usize) {
    let mut line = 1;
    let mut line_start = 0;
    for (idx, ch) in input.char_indices() {
        if idx >= byte_pos {
            break;
        }
        if ch == '\n' {
            line += 1;
            line_start = idx + 1;
        }
    }
    (line, byte_pos.saturating_sub(line_start) + 1)
}

fn detect_bearer(input: &str) -> Vec<Finding> {
    let regex = Regex::new(r"(?i)Authorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/=-]{8,})").unwrap();
    regex
        .captures_iter(input)
        .filter_map(|captures| {
            finding_from_capture(
                input,
                &captures,
                1,
                SecretKind::BearerToken,
                DetectorSource::HeaderDetector,
                Confidence::High,
            )
        })
        .collect()
}

fn detect_cookie_values(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut offset = 0;
    for line in input.split_inclusive('\n') {
        if let Some(header_start) = line.to_ascii_lowercase().find("cookie:") {
            let value_start = header_start + "cookie:".len();
            let cookie_text = &line[value_start..];
            let cookie_base = offset + value_start;
            let mut part_offset = 0;
            for part in cookie_text.split(';') {
                if let Some(eq_idx) = part.find('=') {
                    let key = part[..eq_idx].trim();
                    let raw_value = &part[eq_idx + 1..];
                    let leading_ws = raw_value.len() - raw_value.trim_start().len();
                    let trimmed = raw_value.trim();
                    if should_redact_cookie_value(key, trimmed) {
                        let start = cookie_base + part_offset + eq_idx + 1 + leading_ws;
                        let end = start + trimmed.len();
                        findings.push(make_finding(
                            input,
                            start,
                            end,
                            SecretKind::CookieValue,
                            DetectorSource::CookieDetector,
                            Confidence::High,
                        ));
                    }
                }
                part_offset += part.len() + 1;
            }
        }
        offset += line.len();
    }
    findings
}

fn should_redact_cookie_value(key: &str, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let key = key.to_ascii_lowercase();
    value.len() >= 8
        || key.contains("session")
        || key.contains("token")
        || key.contains("auth")
        || key.contains("secret")
}

fn detect_env_values(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut offset = 0;
    for line in input.split_inclusive('\n') {
        let trimmed_start = line.trim_start();
        if trimmed_start.starts_with('#') {
            offset += line.len();
            continue;
        }
        if let Some(eq_idx) = line.find('=') {
            let key = line[..eq_idx].trim();
            if is_sensitive_key(key) {
                let raw_value = line[eq_idx + 1..].trim_end_matches(['\n', '\r']);
                let leading_ws = raw_value.len() - raw_value.trim_start().len();
                let value = raw_value.trim();
                if !value.is_empty() {
                    let start = offset + eq_idx + 1 + leading_ws;
                    let end = start + value.len();
                    findings.push(make_finding(
                        input,
                        start,
                        end,
                        SecretKind::EnvValue,
                        DetectorSource::EnvDetector,
                        Confidence::High,
                    ));
                }
            }
        }
        offset += line.len();
    }
    findings
}

fn is_sensitive_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD"]
        .iter()
        .any(|needle| upper.contains(needle))
}

fn detect_url_query_secrets(input: &str) -> Vec<Finding> {
    let regex =
        Regex::new(r"([?&])([A-Za-z0-9_-]*(?:token|key|secret|password)[A-Za-z0-9_-]*)=([^&\s]+)")
            .unwrap();
    regex
        .captures_iter(input)
        .filter_map(|captures| {
            finding_from_capture(
                input,
                &captures,
                3,
                SecretKind::UrlQuerySecret,
                DetectorSource::UrlQueryDetector,
                Confidence::High,
            )
        })
        .collect()
}

fn detect_known_secrets(input: &str) -> Vec<Finding> {
    let specs = [
        (r"sk-(?:proj-)?[A-Za-z0-9_-]{10,}", SecretKind::OpenAiKey),
        (r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", SecretKind::AwsAccessKey),
        (r"\bgh[ps]_[A-Za-z0-9_]{10,}\b", SecretKind::GithubToken),
        (
            r"\b(?:sk_live|pk_live)_[A-Za-z0-9_]{10,}\b",
            SecretKind::StripeKey,
        ),
    ];

    let mut findings = Vec::new();
    for (pattern, kind) in specs {
        let regex = Regex::new(pattern).unwrap();
        findings.extend(regex.find_iter(input).map(|matched| {
            make_finding(
                input,
                matched.start(),
                matched.end(),
                kind,
                DetectorSource::KnownSecretDetector,
                Confidence::High,
            )
        }));
    }
    findings
}

fn detect_jwt(input: &str) -> Vec<Finding> {
    let regex = Regex::new(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap();
    regex
        .find_iter(input)
        .map(|matched| {
            make_finding(
                input,
                matched.start(),
                matched.end(),
                SecretKind::Jwt,
                DetectorSource::JwtDetector,
                Confidence::High,
            )
        })
        .collect()
}

fn detect_entropy_context(input: &str) -> Vec<Finding> {
    let regex =
        Regex::new(r"(?i)(?:key|token|secret|password|auth)\s*[:=]\s*([A-Za-z0-9+/=_-]{20,})")
            .unwrap();
    regex
        .captures_iter(input)
        .filter_map(|captures| {
            finding_from_capture(
                input,
                &captures,
                1,
                SecretKind::HighEntropyToken,
                DetectorSource::EntropyDetector,
                Confidence::Medium,
            )
        })
        .collect()
}

fn finding_from_capture(
    input: &str,
    captures: &regex::Captures<'_>,
    index: usize,
    kind: SecretKind,
    source: DetectorSource,
    confidence: Confidence,
) -> Option<Finding> {
    captures.get(index).map(|matched| {
        make_finding(
            input,
            matched.start(),
            matched.end(),
            kind,
            source,
            confidence,
        )
    })
}

fn make_finding(
    input: &str,
    start: usize,
    end: usize,
    kind: SecretKind,
    source: DetectorSource,
    confidence: Confidence,
) -> Finding {
    Finding {
        kind,
        span: ByteSpan { start, end },
        confidence,
        source,
        original: input[start..end].to_owned(),
    }
}
