use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_line, write_all_timeout, App};
use crate::shell::{self, Persona};
use crate::util::{jitter_ms, preview, truncate, MAX_FIELD};
use russh::keys::{ssh_key::LineEnding, Algorithm, PrivateKey};
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, SshId};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;

const BANNER: &[u8] = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";

pub fn load_host_key(path: Option<&Path>) -> anyhow::Result<PrivateKey> {
    if let Some(path) = path {
        if path.exists() {
            return Ok(PrivateKey::read_openssh_file(path)?);
        }
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        key.write_openssh_file(path, LineEnding::LF)?;
        tracing::info!(path = %path.display(), "wrote SSH host key");
        return Ok(key);
    }
    Ok(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?)
}

pub fn server_config(key: PrivateKey) -> russh::server::Config {
    let mut config = russh::server::Config::default();
    config.keys.push(key);
    config.server_id = SshId::Standard("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".into());
    config.methods = MethodSet::from([MethodKind::Password].as_slice());
    config.auth_rejection_time = Duration::from_millis(50);
    config.auth_rejection_time_initial = Some(Duration::from_millis(0));
    config.inactivity_timeout = Some(Duration::from_secs(60));
    config.keepalive_interval = Some(Duration::from_secs(30));
    config
}

pub async fn handle(sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    if let Some(cfg) = app.ssh.clone() {
        app.emit(Event::new("ssh", port, peer, Kind::Connect));
        let handler = Trap {
            app: app.clone(),
            peer,
            port,
            user: String::new(),
            buf: Vec::new(),
            commands: 0,
        };
        let _ = russh::server::run_stream(cfg, sock, handler).await;
        app.emit(Event::new("ssh", port, peer, Kind::Disconnect));
        return;
    }
    banner_only(sock, peer, app, port).await;
}

async fn banner_only(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.emit(Event::new("ssh", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;
    let _ = write_all_timeout(&mut sock, BANNER, app.read_timeout).await;
    match read_line(&mut sock, 256, app.read_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            let ident = String::from_utf8_lossy(&buf);
            let ident = ident.trim();
            let mut ev = Event::new("ssh", port, peer, Kind::Probe)
                .bytes(buf.len())
                .data(preview(&buf));
            if ident.starts_with("SSH-") {
                ev = ev.client(truncate(ident, MAX_FIELD));
            }
            app.emit(ev);
        }
        _ => {
            app.emit(Event::new("ssh", port, peer, Kind::Probe).data("connect-no-data"));
        }
    }
    app.emit(Event::new("ssh", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

struct Trap {
    app: App,
    peer: SocketAddr,
    port: u16,
    user: String,
    buf: Vec<u8>,
    commands: usize,
}

impl Trap {
    fn reject_proxy() -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::Password].as_slice())),
            partial_success: false,
        }
    }

    fn write_prompt(&self, channel: ChannelId, session: &mut Session) {
        let mut out = Vec::from(shell::motd(Persona::Ubuntu));
        out.extend_from_slice(shell::prompt(Persona::Ubuntu));
        let _ = session.data(channel, out);
    }

    fn on_line(&mut self, channel: ChannelId, session: &mut Session, line: &str) {
        let input = line.trim();
        if input.eq_ignore_ascii_case("exit")
            || input.eq_ignore_ascii_case("logout")
            || input.eq_ignore_ascii_case("quit")
        {
            let _ = session.close(channel);
            return;
        }
        if input.is_empty() {
            let _ = session.data(channel, shell::prompt(Persona::Ubuntu));
            return;
        }
        self.commands += 1;
        self.app.emit(
            Event::new("ssh", self.port, self.peer, Kind::Command)
                .user(self.user.clone())
                .data(truncate(input, MAX_FIELD)),
        );
        let mut out = shell::reply(Persona::Ubuntu, input).into_bytes();
        out.extend_from_slice(shell::prompt(Persona::Ubuntu));
        let _ = session.data(channel, out);
        if self.commands >= self.app.max_lines {
            let _ = session.close(channel);
        }
    }
}

impl Handler for Trap {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.user = truncate(user, MAX_FIELD);
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::Password].as_slice())),
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.user = truncate(user, MAX_FIELD);
        self.app.emit(
            Event::new("ssh", self.port, self.peer, Kind::Password)
                .user(self.user.clone())
                .pass(truncate(password, MAX_FIELD)),
        );
        // StingBox HackerCam: any password "succeeds" into a fake shell.
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.user = truncate(user, MAX_FIELD);
        Ok(Self::reject_proxy())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.app.emit(
            Event::new("ssh", self.port, self.peer, Kind::Command)
                .user(self.user.clone())
                .data(format!("direct-tcpip {host_to_connect}:{port_to_connect}"))
                .client("proxy-refused"),
        );
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.app.emit(
            Event::new("ssh", self.port, self.peer, Kind::Command)
                .user(self.user.clone())
                .data(format!("tcpip-forward {address}:{port}"))
                .client("proxy-refused"),
        );
        Ok(false)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.write_prompt(channel, session);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data);
        self.on_line(channel, session, &cmd);
        let _ = session.eof(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.buf.extend_from_slice(data);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n' || b == b'\r') {
            let line = String::from_utf8_lossy(&self.buf[..pos]).into_owned();
            let nl = self.buf[pos];
            self.buf.drain(..=pos);
            if nl == b'\r' && self.buf.first() == Some(&b'\n') {
                self.buf.remove(0);
            }
            self.on_line(channel, session, &line);
        }
        if self.buf.len() > 4096 {
            self.buf.clear();
        }
        Ok(())
    }
}
