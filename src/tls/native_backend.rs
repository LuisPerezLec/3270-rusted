//! The native-tls backend: whatever the operating system supports.
//!
//! OpenSSL on Linux, SChannel on Windows, Secure Transport on macOS. Use this
//! when the host offers suites rustls declines to implement — static RSA, DHE,
//! CBC — or an older protocol version. The operating system's stack decides
//! what is acceptable, which is exactly the point.
//!
//! The trade is a build-time dependency. On Linux `native-tls` links the system
//! OpenSSL and needs its headers (`libssl-dev` or `openssl-devel`). Where those
//! cannot be installed, the `tls-native-vendored` feature compiles OpenSSL from
//! source instead, needing only a C compiler and perl.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use native_tls::{Certificate, Protocol, TlsConnector as NativeConnector};

use super::{TlsConnector, TlsStream, Verification};

/// TLS through the operating system's stack.
#[derive(Debug, Clone)]
pub struct NativeTlsConfig {
    ca_pems: Vec<Vec<u8>>,
    verification: Verification,
    min_version: Option<Protocol>,
    max_version: Option<Protocol>,
    use_built_in_roots: bool,
}

impl Default for NativeTlsConfig {
    fn default() -> Self {
        NativeTlsConfig {
            ca_pems: Vec::new(),
            verification: Verification::Full,
            // Leave the range to the operating system by default. A host that
            // needs TLS 1.0 is reachable only if the OS still allows it.
            min_version: None,
            max_version: None,
            use_built_in_roots: true,
        }
    }
}

impl NativeTlsConfig {
    /// Trust the operating system's certificate store.
    pub fn with_system_roots() -> NativeTlsConfig {
        NativeTlsConfig::default()
    }

    /// Trust exactly the certificate authorities in a PEM file.
    ///
    /// The enterprise case. The file may hold several certificates, and the
    /// system store is left out so the trust set is only what is named here.
    pub fn with_ca_file(path: impl AsRef<std::path::Path>) -> io::Result<NativeTlsConfig> {
        let path = path.as_ref();
        let pem = std::fs::read(path)?;
        let mut ca_pems = Vec::new();
        // native_tls::Certificate::from_pem takes one certificate, so split the
        // file on the PEM boundaries first.
        for block in split_pem(&pem) {
            ca_pems.push(block);
        }
        if ca_pems.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} contains no CERTIFICATE blocks", path.display()),
            ));
        }
        Ok(NativeTlsConfig {
            ca_pems,
            use_built_in_roots: false,
            ..NativeTlsConfig::default()
        })
    }

    /// Accept any certificate without checking it. Testing only; it removes
    /// authentication entirely.
    pub fn insecure() -> NativeTlsConfig {
        NativeTlsConfig {
            verification: Verification::None,
            ..NativeTlsConfig::default()
        }
    }

    /// Set how much of the certificate chain to check.
    pub fn verification(mut self, verification: Verification) -> NativeTlsConfig {
        self.verification = verification;
        self
    }

    /// Offer TLS 1.2 only.
    pub fn tls12_only(mut self) -> NativeTlsConfig {
        self.min_version = Some(Protocol::Tlsv12);
        self.max_version = Some(Protocol::Tlsv12);
        self
    }

    /// Allow TLS 1.0 and later.
    ///
    /// For a host that has not been updated this century. Whether it actually
    /// works depends on the operating system still permitting TLS 1.0; a modern
    /// OpenSSL build usually does not without a configuration change of its own.
    pub fn allow_legacy_versions(mut self) -> NativeTlsConfig {
        self.min_version = Some(Protocol::Tlsv10);
        self.max_version = None;
        self
    }

    /// Set the acceptable protocol range explicitly.
    pub fn protocol_range(
        mut self,
        min: Option<Protocol>,
        max: Option<Protocol>,
    ) -> NativeTlsConfig {
        self.min_version = min;
        self.max_version = max;
        self
    }

    /// Also trust the operating system's certificate store, alongside any CA
    /// file supplied.
    pub fn with_built_in_roots(mut self, enable: bool) -> NativeTlsConfig {
        self.use_built_in_roots = enable;
        self
    }

    fn build(&self) -> io::Result<NativeConnector> {
        let mut builder = NativeConnector::builder();
        for pem in &self.ca_pems {
            let cert = Certificate::from_pem(pem)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad CA: {e}")))?;
            builder.add_root_certificate(cert);
        }
        builder.disable_built_in_roots(!self.use_built_in_roots);
        builder.min_protocol_version(self.min_version);
        builder.max_protocol_version(self.max_version);
        if self.verification.skips_chain() {
            builder.danger_accept_invalid_certs(true);
        }
        if self.verification.skips_hostname() {
            builder.danger_accept_invalid_hostnames(true);
        }
        builder
            .build()
            .map_err(|e| io::Error::other(format!("TLS setup failed: {e}")))
    }
}

impl TlsConnector for NativeTlsConfig {
    fn connect(&self, socket: TcpStream, server_name: &str) -> io::Result<Box<dyn TlsStream>> {
        let connector = self.build()?;
        match connector.connect(server_name, socket) {
            Ok(stream) => Ok(Box::new(NativeStream(stream))),
            Err(native_tls::HandshakeError::Failure(e)) => Err(io::Error::other(format!(
                "TLS handshake failed: {e}{}",
                hint(&e.to_string())
            ))),
            Err(native_tls::HandshakeError::WouldBlock(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS handshake would block; the socket must be in blocking mode",
            )),
        }
    }

    fn backend(&self) -> &'static str {
        "native-tls"
    }
}

/// Turn the two failures that actually happen into advice.
fn hint(message: &str) -> &'static str {
    let m = message.to_ascii_lowercase();
    if m.contains("unsupported protocol") || m.contains("no protocols available") {
        "\n  note: the operating system refused the protocol version. A host \
needing TLS 1.0\n  or 1.1 requires the OS to permit it: on Linux lower \
SECLEVEL or set MinProtocol\n  in openssl.cnf."
    } else if m.contains("handshake failure") || m.contains("no ciphers") {
        "\n  note: no cipher suite in common. The operating system's default \
list may exclude\n  what this host offers; on Linux try \
`openssl ciphers -v 'DEFAULT:@SECLEVEL=0'` to see\n  what is available, and \
`openssl s_client -connect host:port -cipher ...` to confirm."
    } else if m.contains("certificate verify failed") || m.contains("unable to get local issuer") {
        "\n  note: the chain did not verify. Supply the issuing CA with \
NativeTlsConfig::with_ca_file."
    } else {
        ""
    }
}

#[derive(Debug)]
struct NativeStream(native_tls::TlsStream<TcpStream>);

impl Read for NativeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for NativeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl TlsStream for NativeStream {
    fn socket(&self) -> &TcpStream {
        self.0.get_ref()
    }

    // native-tls exposes neither the negotiated version nor the cipher suite,
    // so these stay None. Use `openssl s_client` when the exact suite matters.
}

/// Split a PEM file into its individual certificate blocks.
fn split_pem(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start..];
        let Some(end) = after.find(END) else { break };
        let block = &after[..end + END.len()];
        out.push(block.as_bytes().to_vec());
        rest = &after[end + END.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_ca_file_is_an_error_not_a_panic() {
        assert!(NativeTlsConfig::with_ca_file("/nonexistent/ca.pem").is_err());
    }

    #[test]
    fn a_file_with_no_certificates_is_rejected() {
        let path = std::env::temp_dir().join("tn3270-native-empty.pem");
        std::fs::write(&path, b"not a certificate\n").unwrap();
        let err = NativeTlsConfig::with_ca_file(&path).unwrap_err();
        assert!(
            err.to_string().contains("no CERTIFICATE blocks"),
            "unhelpful error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_pem_file_with_several_certificates_splits_into_all_of_them() {
        let pem = b"\
-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\
junk between blocks\n\
-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
        let blocks = split_pem(pem);
        assert_eq!(blocks.len(), 2);
        assert!(String::from_utf8_lossy(&blocks[0]).contains("AAAA"));
        assert!(String::from_utf8_lossy(&blocks[1]).contains("BBBB"));
    }

    #[test]
    fn a_truncated_pem_block_is_ignored_rather_than_half_read() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n";
        assert!(split_pem(pem).is_empty());
    }

    #[test]
    fn version_pinning_is_recorded() {
        // native_tls::Protocol has no PartialEq, so match on the variant.
        let c = NativeTlsConfig::default();
        assert!(c.min_version.is_none(), "the OS decides by default");
        assert!(c.max_version.is_none());

        let pinned = c.tls12_only();
        assert!(matches!(pinned.min_version, Some(Protocol::Tlsv12)));
        assert!(matches!(pinned.max_version, Some(Protocol::Tlsv12)));

        let legacy = NativeTlsConfig::default().allow_legacy_versions();
        assert!(matches!(legacy.min_version, Some(Protocol::Tlsv10)));
        assert!(legacy.max_version.is_none(), "no upper bound");
    }

    #[test]
    fn insecure_skips_both_checks() {
        let c = NativeTlsConfig::insecure();
        assert!(c.verification.skips_chain());
        assert!(c.verification.skips_hostname());
        // Full verification skips nothing.
        let f = NativeTlsConfig::default();
        assert!(!f.verification.skips_chain());
        assert!(!f.verification.skips_hostname());
    }

    #[test]
    fn a_ca_file_replaces_the_system_roots_by_default() {
        // Trusting one internal CA should not silently also trust everything
        // the operating system trusts.
        let dir = std::env::temp_dir();
        let path = dir.join("tn3270-native-one.pem");
        std::fs::write(
            &path,
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let c = NativeTlsConfig::with_ca_file(&path).unwrap();
        assert!(!c.use_built_in_roots);
        assert!(c.with_built_in_roots(true).use_built_in_roots);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hints_name_the_likely_cause() {
        assert!(hint("unsupported protocol").contains("protocol version"));
        assert!(hint("sslv3 alert handshake failure").contains("cipher suite"));
        assert!(hint("certificate verify failed").contains("with_ca_file"));
        assert_eq!(hint("something else entirely"), "");
    }
}
