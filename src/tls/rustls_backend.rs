//! The rustls backend: modern suites only, no system dependency.
//!
//! Supports ECDHE key exchange with AEAD ciphers, over TLS 1.2 and 1.3. See the
//! parent module for when that is not enough.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use super::{TlsConnector, TlsStream, Verification};

/// How to establish TLS.
#[derive(Clone)]
pub struct RustlsConfig {
    roots: Option<Arc<RootCertStore>>,
    verification: Verification,
    tls12_only: bool,
}

impl std::fmt::Debug for RustlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsConfig")
            .field("verification", &self.verification)
            .field("tls12_only", &self.tls12_only)
            .finish()
    }
}

impl RustlsConfig {
    /// Trust the public root certificates bundled with `webpki-roots`.
    ///
    /// Rarely the right choice for a mainframe, whose certificate is usually
    /// issued internally. See [`RustlsConfig::with_ca_file`].
    pub fn with_webpki_roots() -> RustlsConfig {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        RustlsConfig {
            roots: Some(Arc::new(roots)),
            verification: Verification::Full,
            tls12_only: false,
        }
    }

    /// Trust exactly the certificate authorities in a PEM file.
    ///
    /// This is the enterprise case: export the internal CA and point at it.
    /// The file may hold several certificates.
    pub fn with_ca_file(path: impl AsRef<std::path::Path>) -> io::Result<RustlsConfig> {
        let path = path.as_ref();
        let pem = std::fs::read(path)?;
        let mut reader = io::BufReader::new(pem.as_slice());
        let mut roots = RootCertStore::empty();
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert?;
            roots.add(cert).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} holds a certificate rustls rejected: {e}",
                        path.display()
                    ),
                )
            })?;
            added += 1;
        }
        if added == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} contains no CERTIFICATE blocks", path.display()),
            ));
        }
        Ok(RustlsConfig {
            roots: Some(Arc::new(roots)),
            verification: Verification::Full,
            tls12_only: false,
        })
    }

    /// Accept any certificate without checking it.
    ///
    /// For a first smoke test against a host whose CA you do not have yet.
    /// It removes authentication entirely: anything on the path can read and
    /// alter the session, so do not leave it in place.
    pub fn insecure() -> RustlsConfig {
        RustlsConfig {
            roots: None,
            verification: Verification::None,
            tls12_only: false,
        }
    }

    /// Offer TLS 1.2 only.
    ///
    /// Useful to prove a 1.2-only host really is reached over 1.2, and to fail
    /// loudly rather than silently negotiating 1.3 somewhere else.
    pub fn tls12_only(mut self) -> RustlsConfig {
        self.tls12_only = true;
        self
    }

    /// Set how much of the certificate chain to check.
    pub fn verification(mut self, verification: Verification) -> RustlsConfig {
        self.verification = verification;
        self
    }

    /// Build the rustls client configuration.
    fn build(&self) -> Result<Arc<ClientConfig>, TlsError> {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if self.tls12_only {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS12, &rustls::version::TLS13]
        };
        let builder = ClientConfig::builder_with_protocol_versions(versions);
        let config = if self.verification.skips_chain() {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth()
        } else if self.verification.skips_hostname() {
            // Verify the chain but not the name. Signature verification is
            // delegated to the standard verifier, so only the name check is
            // actually skipped.
            let roots = self
                .roots
                .clone()
                .unwrap_or_else(|| Arc::new(RootCertStore::empty()));
            let inner = rustls::client::WebPkiServerVerifier::builder(roots.clone())
                .build()
                .map_err(|e| TlsError::General(format!("cannot build verifier: {e}")))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ChainOnly {
                    roots,
                    inner,
                    algs: rustls::crypto::ring::default_provider()
                        .signature_verification_algorithms,
                }))
                .with_no_client_auth()
        } else {
            let roots = self
                .roots
                .clone()
                .unwrap_or_else(|| Arc::new(RootCertStore::empty()));
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        Ok(Arc::new(config))
    }
}

impl TlsConnector for RustlsConfig {
    fn connect(&self, socket: TcpStream, server_name: &str) -> io::Result<Box<dyn TlsStream>> {
        let config = self
            .build()
            .map_err(|e| io::Error::other(format!("TLS setup failed: {e}")))?;
        let name = ServerName::try_from(server_name.to_string()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{server_name:?} is not a valid DNS name or IP address"),
            )
        })?;
        let mut conn = rustls::ClientConnection::new(config, name)
            .map_err(|e| io::Error::other(format!("TLS setup failed: {e}")))?;
        let mut socket = socket;
        // Complete the handshake now, so failures are attributable to this call.
        while conn.is_handshaking() {
            conn.complete_io(&mut socket).map_err(|e| {
                io::Error::new(e.kind(), format!("TLS handshake failed: {e}{}", hint(&e)))
            })?;
        }
        Ok(Box::new(RustlsStream(rustls::StreamOwned::new(
            conn, socket,
        ))))
    }

    fn backend(&self) -> &'static str {
        "rustls"
    }
}

/// rustls refuses whole families of suites by design, and the resulting alert
/// looks like a misconfiguration. Say so.
fn hint(e: &io::Error) -> &'static str {
    if e.to_string().contains("HandshakeFailure") {
        "\n  note: rustls offers only ECDHE suites with AEAD ciphers over TLS 1.2 \
and 1.3.\n  A host offering static-RSA or DHE suites, or TLS 1.0/1.1, has \
nothing in common\n  with it. Try the native-tls backend \
(--features tls-native)."
    } else {
        ""
    }
}

#[derive(Debug)]
struct RustlsStream(rustls::StreamOwned<rustls::ClientConnection, TcpStream>);

impl Read for RustlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for RustlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl TlsStream for RustlsStream {
    fn socket(&self) -> &TcpStream {
        &self.0.sock
    }

    fn protocol(&self) -> Option<String> {
        self.0.conn.protocol_version().map(|v| format!("{v:?}"))
    }

    fn cipher(&self) -> Option<String> {
        self.0
            .conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
    }
}

/// Verifies the certificate chain but not the host name.
///
/// See [`Verification::SkipHostname`]. Signature verification is delegated to
/// the standard verifier, so the only check removed is the name.
#[derive(Debug)]
struct ChainOnly {
    roots: Arc<RootCertStore>,
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.algs.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A verifier that accepts everything. See [`RustlsConfig::insecure`].
#[derive(Debug)]
struct NoVerification;

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_ca_file_is_an_error_not_a_panic() {
        assert!(RustlsConfig::with_ca_file("/nonexistent/ca.pem").is_err());
    }

    #[test]
    fn a_file_with_no_certificates_is_rejected() {
        let dir = std::env::temp_dir().join("tn3270-tls-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.pem");
        std::fs::write(&path, b"not a certificate\n").unwrap();
        let err = RustlsConfig::with_ca_file(&path).unwrap_err();
        assert!(
            err.to_string().contains("no CERTIFICATE blocks"),
            "unhelpful error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn configurations_build() {
        assert!(RustlsConfig::insecure().build().is_ok());
        assert!(RustlsConfig::insecure().tls12_only().build().is_ok());
        assert!(RustlsConfig::with_webpki_roots().build().is_ok());
    }

    #[test]
    fn tls12_only_is_recorded() {
        let c = RustlsConfig::insecure();
        assert!(!c.tls12_only);
        assert!(c.tls12_only().tls12_only);
    }
}
