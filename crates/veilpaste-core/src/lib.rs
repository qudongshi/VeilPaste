use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
    BasicAuth,
    ApiKeyHeader,
    Jwt,
    CookieValue,
    OpenAiKey,
    AwsAccessKey,
    GithubToken,
    StripeKey,
    EnvValue,
    DatabaseUrl,
    RedisUrl,
    MongoUri,
    SentryDsn,
    WebhookUrl,
    UrlUserInfo,
    PemPrivateKey,
    NpmToken,
    PypircSecret,
    DockerAuth,
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
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub created_at: String,
    pub entries: Vec<MappingEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct ScrubOptions {
    pub preview: bool,
    pub strict: bool,
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
            session_id: new_session_id(),
            created_at: current_unix_timestamp().to_string(),
            entries: self.mappings.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VeilPasteError {
    #[error("invalid mapping store version: {0}")]
    InvalidMappingVersion(u8),
}

pub fn scrub(input: &str, options: ScrubOptions) -> Result<ScrubResult, VeilPasteError> {
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

pub fn restore(input: &str, mapping: &MappingStore) -> Result<String, VeilPasteError> {
    if mapping.version != 0 && mapping.version != 1 {
        return Err(VeilPasteError::InvalidMappingVersion(mapping.version));
    }

    let mut output = input.to_owned();
    for entry in &mapping.entries {
        if is_valid_placeholder(&entry.placeholder) {
            output = output.replace(&entry.placeholder, &entry.original);
        }
    }
    Ok(output)
}

fn new_session_id() -> String {
    format!("session-{}", current_unix_timestamp())
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn is_valid_placeholder(placeholder: &str) -> bool {
    let Some(body) = placeholder
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    let Some((prefix, count)) = body.rsplit_once('_') else {
        return false;
    };
    !prefix.is_empty()
        && !count.is_empty()
        && prefix
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && count.chars().all(|ch| ch.is_ascii_digit())
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
            SecretKind::BasicAuth => "BASIC_AUTH",
            SecretKind::ApiKeyHeader => "API_KEY_HEADER",
            SecretKind::Jwt => "JWT",
            SecretKind::CookieValue => "COOKIE",
            SecretKind::OpenAiKey => "OPENAI_KEY",
            SecretKind::AwsAccessKey => "AWS_KEY",
            SecretKind::GithubToken => "GITHUB_TOKEN",
            SecretKind::StripeKey => "STRIPE_KEY",
            SecretKind::EnvValue => "ENV_SECRET",
            SecretKind::DatabaseUrl => "DATABASE_URL",
            SecretKind::RedisUrl => "REDIS_URL",
            SecretKind::MongoUri => "MONGO_URI",
            SecretKind::SentryDsn => "SENTRY_DSN",
            SecretKind::WebhookUrl => "WEBHOOK_URL",
            SecretKind::UrlUserInfo => "URL_USERINFO",
            SecretKind::PemPrivateKey => "PEM_PRIVATE_KEY",
            SecretKind::NpmToken => "NPM_TOKEN",
            SecretKind::PypircSecret => "PYPIRC_SECRET",
            SecretKind::DockerAuth => "DOCKER_AUTH",
            SecretKind::UrlQuerySecret => "URL_TOKEN",
            SecretKind::HighEntropyToken => "HIGH_ENTROPY",
        }
    }
}

fn detect_all(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_bearer(input));
    findings.extend(detect_basic_auth(input));
    findings.extend(detect_api_key_headers(input));
    findings.extend(detect_cookie_values(input));
    findings.extend(detect_service_urls(input));
    findings.extend(detect_env_values(input));
    findings.extend(detect_url_userinfo(input));
    findings.extend(detect_url_query_secrets(input));
    findings.extend(detect_known_secrets(input));
    findings.extend(detect_pem_private_keys(input));
    findings.extend(detect_package_credentials(input));
    findings.extend(detect_docker_auth(input));
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

fn detect_basic_auth(input: &str) -> Vec<Finding> {
    let regex = Regex::new(r"(?i)Authorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})").unwrap();
    regex
        .captures_iter(input)
        .filter_map(|captures| {
            finding_from_capture(
                input,
                &captures,
                1,
                SecretKind::BasicAuth,
                DetectorSource::HeaderDetector,
                Confidence::High,
            )
        })
        .collect()
}

fn detect_api_key_headers(input: &str) -> Vec<Finding> {
    let regex =
        Regex::new(r"(?i)\b(?:X-Api-Key|X-Auth-Token|Api-Key)\s*[:：]\s*([A-Za-z0-9._~+/=:-]{8,})")
            .unwrap();
    regex
        .captures_iter(input)
        .filter_map(|captures| {
            finding_from_capture(
                input,
                &captures,
                1,
                SecretKind::ApiKeyHeader,
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
                    let trimmed = raw_value
                        .trim()
                        .trim_end_matches(['\'', '"', '`', ')', ']', '}']);
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
                if !value.is_empty() && !value.contains("-----BEGIN") {
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

fn detect_service_urls(input: &str) -> Vec<Finding> {
    let regex = Regex::new(
        r#"(?i)\b(DATABASE_URL|POSTGRES_URL|MYSQL_URL|REDIS_URL|MONGO_URI|SENTRY_DSN|WEBHOOK_URL)\s*=\s*([^\s'"`)\]}<>,]+)"#,
    )
    .unwrap();
    let mut findings = Vec::new();
    let mut offset = 0;
    for line in input.split_inclusive('\n') {
        let trimmed_start = line.trim_start();
        if trimmed_start.starts_with('#') {
            offset += line.len();
            continue;
        }
        for captures in regex.captures_iter(line) {
            let Some(key_match) = captures.get(1) else {
                continue;
            };
            let Some(value_match) = captures.get(2) else {
                continue;
            };
            let key = key_match.as_str();
            let value = trim_secret_value(value_match.as_str());
            if let Some(kind) = service_url_kind(key, value) {
                let start = offset + value_match.start();
                let end = start + value.len();
                findings.push(make_finding(
                    input,
                    start,
                    end,
                    kind,
                    DetectorSource::EnvDetector,
                    Confidence::High,
                ));
            }
        }
        offset += line.len();
    }
    findings
}

fn service_url_kind(key: &str, value: &str) -> Option<SecretKind> {
    let key = key.trim().to_ascii_uppercase();
    if value.is_empty() {
        return None;
    }

    match key.as_str() {
        "DATABASE_URL" | "POSTGRES_URL" | "MYSQL_URL"
            if has_url_scheme(value, &["postgres://", "postgresql://", "mysql://"]) =>
        {
            Some(SecretKind::DatabaseUrl)
        }
        "REDIS_URL" if has_url_scheme(value, &["redis://", "rediss://"]) => {
            Some(SecretKind::RedisUrl)
        }
        "MONGO_URI" if has_url_scheme(value, &["mongodb://", "mongodb+srv://"]) => {
            Some(SecretKind::MongoUri)
        }
        "SENTRY_DSN" if value.starts_with("https://") && value.contains('@') => {
            Some(SecretKind::SentryDsn)
        }
        "WEBHOOK_URL" if is_known_secret_webhook(value) => Some(SecretKind::WebhookUrl),
        _ => None,
    }
}

fn has_url_scheme(value: &str, schemes: &[&str]) -> bool {
    let lower = value.to_ascii_lowercase();
    schemes.iter().any(|scheme| lower.starts_with(scheme))
}

fn is_known_secret_webhook(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("https://hooks.slack.com/")
        || lower.starts_with("https://discord.com/api/webhooks/")
        || lower.starts_with("https://discordapp.com/api/webhooks/")
}

fn trim_secret_value(value: &str) -> &str {
    value.trim().trim_end_matches(is_secret_delimiter)
}

fn is_secret_delimiter(ch: char) -> bool {
    matches!(ch, '\'' | '"' | '`' | ')' | ']' | '}' | '<' | '>' | ',')
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

fn detect_url_userinfo(input: &str) -> Vec<Finding> {
    let regex = Regex::new(r#"https?://([^/\s'"`@]+:[^@\s'"`/]+)@"#).unwrap();
    regex
        .captures_iter(input)
        .filter_map(|captures| {
            finding_from_capture(
                input,
                &captures,
                1,
                SecretKind::UrlUserInfo,
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

fn detect_pem_private_keys(input: &str) -> Vec<Finding> {
    let regex =
        Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
            .unwrap();
    regex
        .find_iter(input)
        .map(|matched| {
            make_finding(
                input,
                matched.start(),
                matched.end(),
                SecretKind::PemPrivateKey,
                DetectorSource::KnownSecretDetector,
                Confidence::High,
            )
        })
        .collect()
}

fn detect_package_credentials(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let npm_regex = Regex::new(r"(?m)_authToken\s*=\s*([^\s]+)").unwrap();
    findings.extend(npm_regex.captures_iter(input).filter_map(|captures| {
        finding_from_capture(
            input,
            &captures,
            1,
            SecretKind::NpmToken,
            DetectorSource::KnownSecretDetector,
            Confidence::High,
        )
    }));

    let pypirc_regex = Regex::new(r"(?mi)^\s*(?:password|token)\s*=\s*([^\s]+)").unwrap();
    findings.extend(pypirc_regex.captures_iter(input).filter_map(|captures| {
        finding_from_capture(
            input,
            &captures,
            1,
            SecretKind::PypircSecret,
            DetectorSource::KnownSecretDetector,
            Confidence::High,
        )
    }));
    findings
}

fn detect_docker_auth(input: &str) -> Vec<Finding> {
    let regex = Regex::new(r#""auth"\s*:\s*"([^"]{8,})""#).unwrap();
    regex
        .captures_iter(input)
        .filter_map(|captures| {
            finding_from_capture(
                input,
                &captures,
                1,
                SecretKind::DockerAuth,
                DetectorSource::KnownSecretDetector,
                Confidence::High,
            )
        })
        .collect()
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
