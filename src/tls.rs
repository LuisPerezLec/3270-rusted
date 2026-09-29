//! TLS via rustls, so there is no OpenSSL to link against.
//!
//! Most mainframe TLS endpoints are 1.2, and many present a certificate signed
//! by an internal corporate CA rather than a public root. Both cases are
//! first-class here:
//!
//! ```no_run
//! use tn3270::tls::TlsConfig;
//! // The usual enterprise case: trust one internal CA, and pin TLS 1.2.
//! let tls = TlsConfig::with_ca_file("corp-ca.pem")?.tls12_only();
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! One caveat on "no C": rustls's default crypto backend, `ring`, contains
//! some C and assembly that cargo builds for you. What this avoids is a
//! dependency on a system OpenSSL and on the x3270 C engine, not literally
//! every line of C.

use std::io;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// How to establish TLS.
#[derive(Clone)]
pub struct TlsConfig {
    roots: Option<Arc<RootCertStore>>,
    insecure: bool,
    tls12_only: bool,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field(
                "verification",
                &if self.insecure { "DISABLED" } else { "enabled" },
            )
            .field("tls12_only", &self.tls12_only)
            .finish()
    }
}

impl TlsConfig {
    /// Trust the public root certificates bundled with `webpki-roots`.
    ///
    /// Rarely the right choice for a mainframe, whose certificate is usually
    /// issued internally. See [`TlsConfig::with_ca_file`].
    pub fn with_webpki_roots() -> TlsConfig {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        TlsConfig {
            roots: Some(Arc::new(roots)),
            insecure: false,
            tls12_only: false,
        }
    }

    /// Trust exactly the certificate authorities in a PEM file.
    ///
    /// This is the enterprise case: export the internal CA and point at it.
    /// The file may hold several certificates.
    pub fn with_ca_file(path: impl AsRef<std::path::Path>) -> io::Result<TlsConfig> {
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
        Ok(TlsConfig {
            roots: Some(Arc::new(roots)),
            insecure: false,
            tls12_only: false,
        })
    }

    /// Accept any certificate without checking it.
    ///
    /// For a first smoke test against a host whose CA you do not have yet.
    /// It removes authentication entirely: anything on the path can read and
    /// alter the session, so do not leave it in place.
    pub fn insecure() -> TlsConfig {
        TlsConfig {
            roots: None,
            insecure: true,
            tls12_only: false,
        }
    }

    /// Offer TLS 1.2 only.
    ///
    /// Useful to prove a 1.2-only host really is reached over 1.2, and to fail
    /// loudly rather than silently negotiating 1.3 somewhere else.
    pub fn tls12_only(mut self) -> TlsConfig {
        self.tls12_only = true;
        self
    }

    /// Build the rustls client configuration.
    pub(crate) fn build(&self) -> Result<Arc<ClientConfig>, TlsError> {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if self.tls12_only {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS12, &rustls::version::TLS13]
        };
        let builder = ClientConfig::builder_with_protocol_versions(versions);
        let config = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
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

/// A verifier that accepts everything. See [`TlsConfig::insecure`].
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
        assert!(TlsConfig::with_ca_file("/nonexistent/ca.pem").is_err());
    }

    #[test]
    fn a_file_with_no_certificates_is_rejected() {
        let dir = std::env::temp_dir().join("tn3270-tls-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.pem");
        std::fs::write(&path, b"not a certificate\n").unwrap();
        let err = TlsConfig::with_ca_file(&path).unwrap_err();
        assert!(
            err.to_string().contains("no CERTIFICATE blocks"),
            "unhelpful error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn configurations_build() {
        assert!(TlsConfig::insecure().build().is_ok());
        assert!(TlsConfig::insecure().tls12_only().build().is_ok());
        assert!(TlsConfig::with_webpki_roots().build().is_ok());
    }

    #[test]
    fn tls12_only_is_recorded() {
        let c = TlsConfig::insecure();
        assert!(!c.tls12_only);
        assert!(c.tls12_only().tls12_only);
    }
}
