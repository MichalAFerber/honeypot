use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_bounded, write_all_timeout, App};
use crate::util::{jitter_ms, preview, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

const SMB2_MAGIC: &[u8] = b"\xfeSMB";
const SMB1_MAGIC: &[u8] = b"\xffSMB";
const NTLMSSP: &[u8] = b"NTLMSSP\0";
const STATUS_MORE_PROCESSING: u32 = 0xC0000016;
const STATUS_LOGON_FAILURE: u32 = 0xC000006D;
const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
const SMB2_NEGOTIATE: u16 = 0;
const SMB2_SESSION_SETUP: u16 = 1;

/// Windows file-server lure (the StingBox shape). Negotiate + NTLM capture only.
/// Never opens a share, never follows PORT-style callbacks.
pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.emit(Event::new("smb", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;

    let mut exchanges = 0usize;
    loop {
        if exchanges >= app.max_lines {
            break;
        }
        let raw = match read_bounded(&mut sock, app.max_read.min(8192), app.idle_timeout).await {
            Ok(buf) if buf.len() >= 8 => buf,
            _ => break,
        };
        exchanges += 1;
        let payload = strip_netbios(&raw);
        let kind = if payload.starts_with(SMB2_MAGIC) {
            "smb2"
        } else if payload.starts_with(SMB1_MAGIC) {
            "smb1"
        } else {
            "unknown"
        };

        app.emit(
            Event::new("smb", port, peer, Kind::Probe)
                .bytes(raw.len())
                .client(kind)
                .data(preview(&payload[..payload.len().min(80)])),
        );

        if let Some(creds) = extract_ntlm_type3(payload) {
            let mut ev = Event::new("smb", port, peer, Kind::Password)
                .user(creds.user)
                .client(creds.workstation);
            if !creds.domain.is_empty() {
                ev = ev.data(format!("domain={}", creds.domain));
            }
            app.emit(ev);
            let _ = write_all_timeout(
                &mut sock,
                &smb2_simple(SMB2_SESSION_SETUP, STATUS_LOGON_FAILURE, 1, 1),
                app.read_timeout,
            )
            .await;
            break;
        }

        if payload.starts_with(SMB2_MAGIC) && payload.len() >= 16 {
            let cmd = u16::from_le_bytes([payload[12], payload[13]]);
            let mid = if payload.len() >= 32 {
                u64::from_le_bytes(payload[24..32].try_into().unwrap_or([0; 8]))
            } else {
                1
            };
            if cmd == SMB2_NEGOTIATE {
                let _ =
                    write_all_timeout(&mut sock, &smb2_negotiate_response(mid), app.read_timeout)
                        .await;
                continue;
            }
            if cmd == SMB2_SESSION_SETUP {
                if let Some(t1) = ntlm_type(payload) {
                    if t1 == 1 {
                        let _ = write_all_timeout(
                            &mut sock,
                            &smb2_session_challenge(mid),
                            app.read_timeout,
                        )
                        .await;
                        continue;
                    }
                }
            }
            let _ = write_all_timeout(
                &mut sock,
                &smb2_simple(cmd, STATUS_ACCESS_DENIED, mid, 1),
                app.read_timeout,
            )
            .await;
        } else if payload.starts_with(SMB1_MAGIC) {
            // SMB1 clients exist on LAN scanners. Do not speak SMB1 for real;
            // log and drop so we are not an SMBv1 amplifier.
            break;
        } else {
            break;
        }
    }

    app.emit(Event::new("smb", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

fn strip_netbios(buf: &[u8]) -> &[u8] {
    if buf.len() >= 4 && buf[0] == 0x00 {
        let n = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        if n > 0 && buf.len() >= 4 + n.min(buf.len() - 4) {
            return &buf[4..];
        }
        return &buf[4..];
    }
    buf
}

#[derive(Debug, PartialEq, Eq)]
pub struct NtlmCreds {
    pub user: String,
    pub domain: String,
    pub workstation: String,
}

pub fn ntlm_type(buf: &[u8]) -> Option<u32> {
    let i = find_sub(buf, NTLMSSP)?;
    if i + 12 > buf.len() {
        return None;
    }
    Some(u32::from_le_bytes(buf[i + 8..i + 12].try_into().ok()?))
}

pub fn extract_ntlm_type3(buf: &[u8]) -> Option<NtlmCreds> {
    let i = find_sub(buf, NTLMSSP)?;
    let msg = &buf[i..];
    if ntlm_type(buf) != Some(3) || msg.len() < 52 {
        return None;
    }
    let domain = ntlm_str(msg, 28)?;
    let user = ntlm_str(msg, 36)?;
    let workstation = ntlm_str(msg, 44).unwrap_or_default();
    if user.is_empty() {
        return None;
    }
    Some(NtlmCreds {
        user: truncate(&user, MAX_FIELD),
        domain: truncate(&domain, MAX_FIELD),
        workstation: truncate(&workstation, MAX_FIELD),
    })
}

fn ntlm_str(msg: &[u8], field_off: usize) -> Option<String> {
    if field_off + 8 > msg.len() {
        return None;
    }
    let len = u16::from_le_bytes(msg[field_off..field_off + 2].try_into().ok()?) as usize;
    let offset = u32::from_le_bytes(msg[field_off + 4..field_off + 8].try_into().ok()?) as usize;
    if offset.checked_add(len)? > msg.len() {
        return None;
    }
    let slice = &msg[offset..offset + len];
    if slice.len() >= 2 && slice.len() % 2 == 0 {
        let u16s: Vec<u16> = slice
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&u16s))
    } else {
        Some(String::from_utf8_lossy(slice).into_owned())
    }
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn netbios_wrap(inner: &[u8]) -> Vec<u8> {
    let n = inner.len() as u32;
    let mut out = Vec::with_capacity(4 + inner.len());
    out.push(0x00);
    out.push(((n >> 16) & 0xff) as u8);
    out.push(((n >> 8) & 0xff) as u8);
    out.push((n & 0xff) as u8);
    out.extend_from_slice(inner);
    out
}

fn smb2_header(cmd: u16, status: u32, message_id: u64, body_len: usize) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(SMB2_MAGIC);
    h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
    h[8..12].copy_from_slice(&status.to_le_bytes());
    h[12..14].copy_from_slice(&cmd.to_le_bytes());
    h[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditResponse
    h[16..20].copy_from_slice(&1u32.to_le_bytes()); // flags: response
    h[24..32].copy_from_slice(&message_id.to_le_bytes());
    h[36..40].copy_from_slice(&((64 + body_len) as u32).to_le_bytes());
    h
}

fn smb2_simple(cmd: u16, status: u32, message_id: u64, _sid: u64) -> Vec<u8> {
    let body = [0x09u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // empty error
    let mut pkt = smb2_header(cmd, status, message_id, body.len());
    pkt.extend_from_slice(&body);
    netbios_wrap(&pkt)
}

fn smb2_negotiate_response(message_id: u64) -> Vec<u8> {
    let mut body = vec![0u8; 64];
    body[0..2].copy_from_slice(&65u16.to_le_bytes()); // StructureSize
    body[2..4].copy_from_slice(&1u16.to_le_bytes()); // signing enabled
    body[4..6].copy_from_slice(&0x0202u16.to_le_bytes()); // SMB 2.0.2
    body[8..24].copy_from_slice(b"FILESERVER\x00\x00\x00\x00\x00\x00"); // guid-ish
    body[28..32].copy_from_slice(&65536u32.to_le_bytes());
    body[32..36].copy_from_slice(&65536u32.to_le_bytes());
    body[36..40].copy_from_slice(&65536u32.to_le_bytes());
    body[56..58].copy_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
    let mut pkt = smb2_header(SMB2_NEGOTIATE, 0, message_id, body.len());
    pkt.extend_from_slice(&body);
    netbios_wrap(&pkt)
}

fn smb2_session_challenge(message_id: u64) -> Vec<u8> {
    // Minimal NTLM Type 2 (challenge) so the client sends Type 3 with the username.
    let mut ntlm = Vec::from(NTLMSSP);
    ntlm.extend_from_slice(&2u32.to_le_bytes());
    ntlm.extend_from_slice(&[0u8; 8]); // target name empty
    ntlm.extend_from_slice(&0x00008201u32.to_le_bytes()); // flags: unicode + NTLM
    ntlm.extend_from_slice(b"\x11\x22\x33\x44\x55\x66\x77\x88"); // challenge
    ntlm.extend_from_slice(&[0u8; 8]);
    ntlm.extend_from_slice(&[0u8; 8]); // target info empty

    let mut body = vec![0u8; 8];
    body[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize
    body[2..4].copy_from_slice(&0u16.to_le_bytes()); // SessionFlags
    let offset = 64 + 8;
    body[4..6].copy_from_slice(&(offset as u16).to_le_bytes());
    body[6..8].copy_from_slice(&(ntlm.len() as u16).to_le_bytes());
    body.extend_from_slice(&ntlm);

    let mut pkt = smb2_header(
        SMB2_SESSION_SETUP,
        STATUS_MORE_PROCESSING,
        message_id,
        body.len(),
    );
    pkt.extend_from_slice(&body);
    netbios_wrap(&pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type3_user() {
        // Hand-built Type 3: user "Administrator" UTF-16 at offset 52, empty domain/workstation.
        let mut msg = vec![0u8; 52];
        msg[0..8].copy_from_slice(NTLMSSP);
        msg[8..12].copy_from_slice(&3u32.to_le_bytes());
        let user: Vec<u8> = "Administrator"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let off = 52u32;
        msg[36..38].copy_from_slice(&(user.len() as u16).to_le_bytes());
        msg[38..40].copy_from_slice(&(user.len() as u16).to_le_bytes());
        msg[40..44].copy_from_slice(&off.to_le_bytes());
        msg.extend_from_slice(&user);
        let got = extract_ntlm_type3(&msg).unwrap();
        assert_eq!(got.user, "Administrator");
    }
}
