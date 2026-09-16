//! A webhook URL that cannot be logged in full.
//!
//! The notify token rides in the URL's query string, so anything that prints
//! the URL prints the credential. [`WebhookUrl`] makes that impossible by
//! construction: both `Display` and `Debug` render only the scheme, host, and
//! port, plus a short fingerprint. Getting at the credential-bearing form takes
//! an explicit [`WebhookUrl::expose`], which only the HTTP client calls.

use std::fmt;
use std::str::FromStr;

/// A webhook URL whose credential-bearing parts never reach a log.
#[derive(Clone)]
pub struct WebhookUrl(String);

impl WebhookUrl {
    /// The full URL, credential included. Only the HTTP client may call this.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `https://host:port#ab12cd34` — enough for an operator to confirm which
    /// endpoint is configured, never enough to post to it.
    ///
    /// The path is dropped along with the query string: some relays (ntfy, for
    /// one) carry the secret as a path segment, so keeping it would reopen this
    /// hole for a different deployment. The fingerprint covers the whole URL, so
    /// two honeypots pointed at the same endpoint still render identically.
    pub fn redacted(&self) -> String {
        format!("{}#{}", scheme_and_host(&self.0), fingerprint(&self.0))
    }
}

impl FromStr for WebhookUrl {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            return Err("webhook URL must not be empty".into());
        }
        Ok(Self(s.to_string()))
    }
}

/// Redacted on purpose: see the module docs.
impl fmt::Display for WebhookUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redacted on purpose, so that `#[derive(Debug)]` on any struct holding one —
/// `Args`, `AlertConfig` — is safe to print.
impl fmt::Debug for WebhookUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebhookUrl({})", self.0)
    }
}

/// The value the startup line logs for the `webhook` field.
pub fn log_field(url: Option<&WebhookUrl>) -> String {
    url.map(|u| u.expose().to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// `scheme://host:port`, with any `user:pass@` userinfo and everything from the
/// first `/`, `?`, or `#` removed.
fn scheme_and_host(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => return "<malformed>".to_string(),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    if authority.is_empty() {
        return "<malformed>".to_string();
    }
    format!("{scheme}://{authority}")
}

/// FNV-1a over the whole URL, truncated to 32 bits. An identity check for
/// operators — "is this the endpoint I configured?" — not a secret, and far too
/// lossy to recover a 64-character token from.
fn fingerprint(url: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in url.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{:08x}", (hash ^ (hash >> 32)) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in shaped like the real thing: HTTPS, a host, a path, and a long
    /// hex token in the query string.
    const SENTINEL: &str =
        "https://notify.example.invalid/notify/honeypot?token=SENTINELTOKEN0123456789abcdef";
    const SENTINEL_TOKEN: &str = "SENTINELTOKEN0123456789abcdef";

    fn sentinel() -> WebhookUrl {
        SENTINEL.parse().expect("parses")
    }

    #[test]
    fn startup_log_field_hides_the_token() {
        let rendered = log_field(Some(&sentinel()));
        assert!(
            !rendered.contains(SENTINEL_TOKEN),
            "startup line leaked the webhook token: {rendered}"
        );
        assert!(
            !rendered.contains('?'),
            "startup line leaked a query string: {rendered}"
        );
        // Still useful: an operator can see which endpoint is configured.
        assert!(
            rendered.contains("notify.example.invalid"),
            "startup line should name the host: {rendered}"
        );
    }

    #[test]
    fn unset_webhook_still_renders_a_dash() {
        assert_eq!(log_field(None), "-");
    }

    #[test]
    fn display_and_debug_both_redact() {
        let url = sentinel();
        for rendered in [format!("{url}"), format!("{url:?}")] {
            assert!(
                !rendered.contains(SENTINEL_TOKEN),
                "formatting leaked the webhook token: {rendered}"
            );
        }
    }

    #[test]
    fn userinfo_credentials_are_dropped_too() {
        let url: WebhookUrl = "https://user:hunter2@relay.example.invalid/hook"
            .parse()
            .unwrap();
        let rendered = url.redacted();
        assert!(!rendered.contains("hunter2"), "leaked userinfo: {rendered}");
        assert!(rendered.contains("relay.example.invalid"));
    }

    #[test]
    fn expose_is_the_only_way_to_the_full_url() {
        assert_eq!(sentinel().expose(), SENTINEL);
    }

    #[test]
    fn fingerprint_identifies_the_endpoint() {
        let a = sentinel();
        let b = sentinel();
        let other: WebhookUrl = "https://notify.example.invalid/notify/honeypot?token=other"
            .parse()
            .unwrap();
        assert_eq!(a.redacted(), b.redacted(), "same URL, same rendering");
        assert_ne!(
            a.redacted(),
            other.redacted(),
            "a different token must be distinguishable"
        );
    }

    #[test]
    fn port_is_kept_and_malformed_input_does_not_leak() {
        let url: WebhookUrl = "http://127.0.0.1:9999/hook?token=abc".parse().unwrap();
        assert!(url.redacted().starts_with("http://127.0.0.1:9999#"));
        let bad: WebhookUrl = "not-a-url?token=abc".parse().unwrap();
        assert!(!bad.redacted().contains("abc"), "malformed input leaked");
    }

    #[test]
    fn empty_is_rejected() {
        assert!("".parse::<WebhookUrl>().is_err());
        assert!("   ".parse::<WebhookUrl>().is_err());
    }
}
