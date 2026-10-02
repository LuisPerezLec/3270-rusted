//! TLS, with a pluggable backend.
//!
//! There are two backends because they suit different hosts, and choosing
//! between them is a real decision rather than a detail:
//!
//! | Backend | Feature | Use it when |
//! |---|---|---|
//! | [`RustlsConfig`] | `tls-rustls` | the host is modern. No system dependency. |
//! | [`NativeTlsConfig`] | `tls-native` | the host is not. Uses the operating system's TLS. |
//!
//! rustls deliberately implements **only ECDHE key exchange with AEAD ciphers**
//! — six suites in TLS 1.2 — and only TLS 1.2 and 1.3. That is a sound security
//! position and wrong for a lot of mainframes, whose TLS stacks commonly offer
//! static-RSA or DHE suites with CBC, such as `TLS_RSA_WITH_AES_128_CBC_SHA`.
//! Against such a host rustls has no suite in common and the handshake fails
//! with `received fatal alert: HandshakeFailure`, which looks like a
//! configuration problem but is not.
//!
//! When that happens, switch backend rather than hunting for a setting:
//!
//! ```no_run
//! # use std::time::Duration;
//! # use tn3270::{Connection, Model, SessionConfig};
//! use tn3270::tls::NativeTlsConfig;
//!
//! let tls = NativeTlsConfig::with_ca_file("corp-ca.pem")?.tls12_only();
//! let conn = Connection::connect_tls(
//!     "mvs.example.com:992",
//!     "mvs.example.com",
//!     SessionConfig::model(Model::Model2),
//!     &tls,
//!     Duration::from_secs(15),
//! )?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! `examples/tls_probe.rs` tries every combination and reports which ones a
//! host accepts, which is faster than reasoning about it.

use std::io::{self, Read, Write};
use std::net::TcpStream;

#[cfg(feature = "tls-native")]
mod native_backend;
#[cfg(feature = "tls-rustls")]
mod rustls_backend;

#[cfg(feature = "tls-native")]
pub use native_backend::NativeTlsConfig;
#[cfg(feature = "tls-rustls")]
pub use rustls_backend::RustlsConfig;

/// An established TLS stream.
///
/// Implement this, and [`TlsConnector`], to plug in a TLS stack this crate does
/// not ship.
pub trait TlsStream: Read + Write + Send + std::fmt::Debug {
    /// The socket underneath, so read timeouts can be set on it. A TLS wrapper
    /// has no timeout of its own.
    fn socket(&self) -> &TcpStream;

    /// The negotiated protocol version, when the backend exposes it.
    fn protocol(&self) -> Option<String> {
        None
    }

    /// The negotiated cipher suite, when the backend exposes it.
    fn cipher(&self) -> Option<String> {
        None
    }
}

/// Something that can wrap a connected socket in TLS.
///
/// The handshake must be completed before returning, so that a certificate or
/// cipher problem is reported from here rather than from the first read.
pub trait TlsConnector {
    fn connect(&self, socket: TcpStream, server_name: &str) -> io::Result<Box<dyn TlsStream>>;

    /// Which stack this is, for diagnostics.
    fn backend(&self) -> &'static str;
}

/// How much of the certificate chain to check.
///
/// Shared by both backends so the choice reads the same either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verification {
    /// Check the chain and the host name. The default, and the only one to use
    /// once the CA is known.
    #[default]
    Full,
    /// Check the chain but not the host name. For a certificate whose name does
    /// not match the address it is reached at.
    SkipHostname,
    /// Check nothing. For a first smoke test against a host whose CA is not
    /// available yet; it removes authentication entirely.
    None,
}

// Only the backends consult these, so they do not exist when the marker
// feature is selected without one.
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
impl Verification {
    pub(crate) fn skips_hostname(self) -> bool {
        matches!(self, Verification::SkipHostname | Verification::None)
    }

    pub(crate) fn skips_chain(self) -> bool {
        matches!(self, Verification::None)
    }
}
