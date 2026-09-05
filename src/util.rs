use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PREVIEW_CHARS: usize = 200;
pub const MAX_FIELD: usize = 256;

pub fn preview(bytes: &[u8]) -> String {
    preview_n(bytes, PREVIEW_CHARS)
}

pub fn preview_n(bytes: &[u8], max_chars: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' || !c.is_control() {
                c
            } else {
                '.'
            }
        })
        .take(max_chars)
        .collect()
}

pub fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    let want = name.to_ascii_lowercase();
    for line in headers.lines() {
        let line = line.trim_end_matches('\r');
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(&want) {
                return Some(v.trim());
            }
        }
    }
    None
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode `Basic base64(user:pass)`. Returns None if the header is not Basic or is malformed.
pub fn decode_basic_auth(value: &str) -> Option<(String, String)> {
    let rest = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?
        .trim();
    let raw = b64_decode(rest)?;
    let s = String::from_utf8(raw).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((truncate(u, MAX_FIELD), truncate(p, MAX_FIELD)))
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(4) {
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            b64_val(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            b64_val(chunk[3])?
        };
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push(((b & 0x0f) << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push(((c & 0x03) << 6) | d);
        }
    }
    Some(out)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub async fn jitter_ms(min: u64, max: u64) {
    if max == 0 || max < min {
        return;
    }
    let span = max - min + 1;
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    tokio::time::sleep(Duration::from_millis(min + (n % span))).await;
}

/// Strip Telnet IAC (0xFF) option negotiation so login prompts see printable text.
pub fn strip_telnet_iac(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == 0xff {
            if i + 1 >= input.len() {
                break;
            }
            let cmd = input[i + 1];
            // IAC IAC is a literal 0xFF
            if cmd == 0xff {
                out.push(0xff);
                i += 2;
                continue;
            }
            // WILL/WONT/DO/DONT + option
            if matches!(cmd, 0xfb..=0xfe) {
                i += 3;
                continue;
            }
            // SB ... IAC SE
            if cmd == 0xfa {
                i += 2;
                while i + 1 < input.len() {
                    if input[i] == 0xff && input[i + 1] == 0xf0 {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            i += 2;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

pub fn parse_form_creds(body: &str) -> (Option<String>, Option<String>) {
    let mut user = None;
    let mut pass = None;
    for part in body.split('&') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let k = percent_decode(k).to_ascii_lowercase();
        let v = truncate(&percent_decode(v), MAX_FIELD);
        if k.contains("user") || k == "login" || k == "name" || k == "account" {
            user = Some(v);
        } else if k.contains("pass") || k == "pwd" || k == "password" {
            pass = Some(v);
        }
    }
    (user, pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_roundtrip() {
        // admin:admin -> YWRtaW46YWRtaW4=
        let got = decode_basic_auth("Basic YWRtaW46YWRtaW4=").unwrap();
        assert_eq!(got, ("admin".into(), "admin".into()));
    }

    #[test]
    fn percent_plus() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
    }

    #[test]
    fn form_creds() {
        let (u, p) = parse_form_creds("username=root&password=xc3511");
        assert_eq!(u.as_deref(), Some("root"));
        assert_eq!(p.as_deref(), Some("xc3511"));
    }

    #[test]
    fn iac_stripped() {
        let raw = [0xff, 0xfd, 0x18, b'r', b'o', b'o', b't', b'\r', b'\n'];
        assert_eq!(strip_telnet_iac(&raw), b"root\r\n");
    }
}
