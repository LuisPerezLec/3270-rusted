//! A blocking TCP transport over the sans-IO [`Session`].
//!
//! The `wait_*` methods are the automation primitives. There is no "end of
//! screen" marker in the 3270 protocol, so knowing when the host has finished
//! painting is the single biggest source of flaky automation. The answer is not
//! a sleep: it is the keyboard-restore bit in the Write Control Character, which
//! [`Connection::wait_until_unlocked`] waits for.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::ds::Aid;
use crate::screen::Screen;
use crate::session::{ActionError, Event, Session, SessionConfig};

/// Why waiting ended without the condition being met.
#[derive(Debug)]
pub enum WaitError {
    /// The deadline passed.
    Timeout,
    /// The peer closed the connection.
    Closed,
    Io(io::Error),
    Action(ActionError),
}

impl core::fmt::Display for WaitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WaitError::Timeout => f.write_str("timed out waiting for the host"),
            WaitError::Closed => f.write_str("the host closed the connection"),
            WaitError::Io(e) => write!(f, "io error: {e}"),
            WaitError::Action(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WaitError {}

impl From<io::Error> for WaitError {
    fn from(e: io::Error) -> Self {
        WaitError::Io(e)
    }
}

impl From<ActionError> for WaitError {
    fn from(e: ActionError) -> Self {
        WaitError::Action(e)
    }
}

/// The byte transport underneath a [`Connection`].
///
/// Read timeouts are set on the underlying socket in both cases, because a TLS
/// wrapper has no timeout of its own.
#[derive(Debug)]
enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Stream {
    fn socket(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => &s.sock,
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket().set_read_timeout(timeout)
    }

    fn shutdown(&self) {
        let _ = self.socket().shutdown(std::net::Shutdown::Both);
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// A connected 3270 session.
#[derive(Debug)]
pub struct Connection {
    stream: Stream,
    session: Session,
    /// Events observed since the caller last drained them.
    seen: Vec<Event>,
}

impl Connection {
    /// Connect and run negotiation to completion.
    pub fn connect(
        addr: impl ToSocketAddrs,
        config: SessionConfig,
        timeout: Duration,
    ) -> Result<Connection, WaitError> {
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no such address"))?;
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nodelay(true)?;
        let mut conn = Connection {
            stream: Stream::Plain(stream),
            session: Session::new(config),
            seen: Vec::new(),
        };
        conn.flush()?;
        conn.wait_until(timeout, |s, _| s.is_connected())?;
        Ok(conn)
    }

    /// Wrap an already-connected socket, for a proxy or a pre-set-up link.
    pub fn from_stream(stream: TcpStream, config: SessionConfig) -> Connection {
        Connection {
            stream: Stream::Plain(stream),
            session: Session::new(config),
            seen: Vec::new(),
        }
    }

    /// Connect over TLS and run negotiation to completion.
    ///
    /// `server_name` is what the certificate must match, and what is sent as
    /// SNI. It is separate from the dial address so a host reached by IP can
    /// still be verified against the name on its certificate.
    ///
    /// The handshake is completed here rather than lazily, so a certificate
    /// problem surfaces as an error from this call instead of from the first
    /// read.
    #[cfg(feature = "tls")]
    pub fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: &str,
        config: SessionConfig,
        tls: &crate::tls::TlsConfig,
        timeout: Duration,
    ) -> Result<Connection, WaitError> {
        use rustls_pki_types::ServerName;

        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no such address"))?;
        let client_config = tls.build().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TLS setup failed: {e}"),
            )
        })?;
        let name = ServerName::try_from(server_name.to_string()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{server_name:?} is not a valid DNS name or IP address"),
            )
        })?;

        let mut socket = TcpStream::connect_timeout(&addr, timeout)?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(timeout))?;
        let mut tls_conn = rustls::ClientConnection::new(client_config, name)
            .map_err(|e| io::Error::other(format!("TLS setup failed: {e}")))?;
        // Drive the handshake now so errors are attributable.
        while tls_conn.is_handshaking() {
            tls_conn
                .complete_io(&mut socket)
                .map_err(|e| io::Error::new(e.kind(), format!("TLS handshake failed: {e}")))?;
        }

        let mut conn = Connection {
            stream: Stream::Tls(Box::new(rustls::StreamOwned::new(tls_conn, socket))),
            session: Session::new(config),
            seen: Vec::new(),
        };
        conn.flush()?;
        conn.wait_until(timeout, |s, _| s.is_connected())?;
        Ok(conn)
    }

    /// The negotiated TLS protocol version and cipher suite, if this connection
    /// is encrypted.
    #[cfg(feature = "tls")]
    pub fn tls_info(&self) -> Option<(rustls::ProtocolVersion, rustls::SupportedCipherSuite)> {
        match &self.stream {
            Stream::Tls(s) => Some((
                s.conn.protocol_version()?,
                s.conn.negotiated_cipher_suite()?,
            )),
            _ => None,
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn screen(&self) -> &Screen {
        self.session.screen()
    }

    /// Events observed so far, cleared by this call.
    pub fn take_events(&mut self) -> Vec<Event> {
        core::mem::take(&mut self.seen)
    }

    /// Write anything the session has queued.
    pub fn flush(&mut self) -> io::Result<()> {
        let out = self.session.take_output();
        if !out.is_empty() {
            self.stream.write_all(&out)?;
            self.stream.flush()?;
        }
        Ok(())
    }

    /// Read once with a deadline, feed the session, then write its reply.
    ///
    /// Returns false when the read timed out without data.
    pub fn pump(&mut self, timeout: Duration) -> Result<bool, WaitError> {
        self.stream
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        let mut buf = [0u8; 8192];
        match self.stream.read(&mut buf) {
            Ok(0) => Err(WaitError::Closed),
            Ok(n) => {
                self.session.receive(&buf[..n]);
                while let Some(event) = self.session.next_event() {
                    self.seen.push(event);
                }
                self.flush()?;
                Ok(true)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(WaitError::Io(e)),
        }
    }

    /// Pump until `predicate` holds, or the deadline passes.
    ///
    /// The predicate sees the session and every event observed while waiting.
    pub fn wait_until<F>(&mut self, timeout: Duration, mut predicate: F) -> Result<(), WaitError>
    where
        F: FnMut(&Session, &[Event]) -> bool,
    {
        let deadline = Instant::now() + timeout;
        if predicate(&self.session, &self.seen) {
            return Ok(());
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(WaitError::Timeout);
            }
            self.pump(left.min(Duration::from_millis(250)))?;
            if predicate(&self.session, &self.seen) {
                return Ok(());
            }
        }
    }

    /// Wait until the host unlocks the keyboard, meaning it has finished
    /// painting and input is allowed.
    pub fn wait_until_unlocked(&mut self, timeout: Duration) -> Result<(), WaitError> {
        self.wait_until(timeout, |s, _| s.is_connected() && !s.is_keyboard_locked())
    }

    /// Wait until the keyboard is unlocked *and* the host has been silent for
    /// `idle`.
    ///
    /// [`Connection::wait_until_unlocked`] returns on the first screen the host
    /// unlocks, which is right for a request/response panel. Some hosts send a
    /// second screen unprompted — a banner followed by a logon panel, or a
    /// status line repainted a moment later — and acting on the first one means
    /// typing into a screen that is about to be replaced.
    ///
    /// This waits for the conversation to go quiet instead. `idle` is a real
    /// delay, so keep it small: 300-500ms is usually enough on a local link,
    /// and it costs that much on every call.
    pub fn wait_for_quiet(&mut self, idle: Duration, timeout: Duration) -> Result<(), WaitError> {
        let deadline = Instant::now() + timeout;
        let mut last_data = Instant::now();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(WaitError::Timeout);
            }
            // Poll in slices no longer than the idle window, so a quiet period
            // is noticed promptly.
            let slice = left.min(idle.max(Duration::from_millis(10)));
            if self.pump(slice)? {
                last_data = Instant::now();
                continue;
            }
            let settled = last_data.elapsed() >= idle;
            if settled && self.session.is_connected() && !self.session.is_keyboard_locked() {
                return Ok(());
            }
        }
    }

    /// Wait until `needle` appears anywhere on the screen.
    pub fn wait_for_text(&mut self, needle: &str, timeout: Duration) -> Result<(), WaitError> {
        let needle = needle.to_string();
        self.wait_until(timeout, move |s, _| s.screen().find(&needle).is_some())
    }

    /// Wait until `needle` appears at a 1-based position.
    pub fn wait_for_text_at(
        &mut self,
        row: u16,
        col: u16,
        needle: &str,
        timeout: Duration,
    ) -> Result<(), WaitError> {
        let needle = needle.to_string();
        self.wait_until(timeout, move |s, _| {
            s.screen().text_at(row, col, needle.chars().count() as u16) == needle
        })
    }

    // ------------------------------------------------------------ actions --

    /// Send an AID and wait for the host to unlock the keyboard again.
    pub fn press(&mut self, aid: Aid, timeout: Duration) -> Result<(), WaitError> {
        self.session.press(aid)?;
        self.flush()?;
        self.wait_until_unlocked(timeout)
    }

    /// Send an AID without waiting.
    pub fn press_now(&mut self, aid: Aid) -> Result<(), WaitError> {
        self.session.press(aid)?;
        self.flush()?;
        Ok(())
    }

    pub fn type_text(&mut self, text: &str) -> Result<(), WaitError> {
        self.session.type_text(text)?;
        Ok(())
    }

    pub fn set_cursor(&mut self, row: u16, col: u16) {
        self.session.set_cursor(row, col);
    }

    pub fn tab(&mut self) {
        self.session.tab();
    }

    /// Type into the field at `row`/`col`, then press Enter and wait.
    pub fn fill_and_enter(
        &mut self,
        row: u16,
        col: u16,
        text: &str,
        timeout: Duration,
    ) -> Result<(), WaitError> {
        self.set_cursor(row, col);
        self.type_text(text)?;
        self.press(Aid::Enter, timeout)
    }

    /// Close the connection.
    pub fn shutdown(&mut self) {
        self.stream.shutdown();
    }
}
