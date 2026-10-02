//! Find out which TLS settings a host will accept.
//!
//! Tries every combination of backend, protocol range and verification level,
//! and reports which ones complete a handshake. It does only the TLS handshake
//! and then disconnects — no 3270 negotiation, no AID — so it is safe to point
//! at a production host.
//!
//!     cargo run --all-features --example tls_probe -- mvs.example.com:992
//!     cargo run --all-features --example tls_probe -- mvs.example.com:992 \
//!         --cafile corp-ca.pem --servername mvs.example.com
//!
//! Build with `--features tls-rustls,tls-native` (or `--all-features`) to test
//! both backends; with only one the other is reported as not compiled in.

use std::net::TcpStream;
use std::time::Duration;

use tn3270::tls::{TlsConnector, Verification};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct Attempt {
    backend: &'static str,
    setting: &'static str,
    verification: Verification,
    result: Result<String, String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args
        .next()
        .ok_or("usage: tls_probe <host:port> [--cafile F] [--servername N]")?;
    let mut cafile: Option<String> = None;
    let mut servername: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cafile" => cafile = args.next(),
            "--servername" => servername = args.next(),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    let name = servername.clone().unwrap_or_else(|| {
        addr.rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| addr.clone())
    });

    println!("probing {addr}, certificate name {name:?}");
    match &cafile {
        Some(f) => println!("trust anchor: {f}"),
        None => {
            println!("trust anchor: system/public roots only (pass --cafile for an internal CA)")
        }
    }
    println!();

    let mut attempts = Vec::new();
    probe_rustls(&addr, &name, cafile.as_deref(), &mut attempts);
    probe_native(&addr, &name, cafile.as_deref(), &mut attempts);

    println!(
        "{:<12} {:<22} {:<14} RESULT",
        "BACKEND", "SETTING", "VERIFY"
    );
    println!("{}", "-".repeat(78));
    for a in &attempts {
        let verify = match a.verification {
            Verification::Full => "full",
            Verification::SkipHostname => "chain only",
            Verification::None => "none",
        };
        let result = match &a.result {
            Ok(info) => format!("OK  {info}"),
            Err(e) => format!("--  {}", first_line(e)),
        };
        println!(
            "{:<12} {:<22} {:<14} {result}",
            a.backend, a.setting, verify
        );
    }

    println!();
    conclude(&attempts);
    Ok(())
}

/// The useful part: turn the matrix into one recommendation.
fn conclude(attempts: &[Attempt]) {
    let worked: Vec<&Attempt> = attempts.iter().filter(|a| a.result.is_ok()).collect();
    if worked.is_empty() {
        println!("Nothing completed a handshake.");
        println!("  * If every row says 'handshake failure', the host wants a cipher suite");
        println!("    neither backend offered. Check with:");
        println!("      openssl s_client -connect <host:port> -tls1_2");
        println!("  * If rows mention the protocol version, the host may need TLS 1.0/1.1,");
        println!("    which the operating system must be configured to permit.");
        println!("  * If the connection is refused outright, the port may not be TLS at all;");
        println!("    try the plain transport.");
        return;
    }

    // Did verification make the difference, or the backend?
    let full_ok = worked.iter().any(|a| a.verification == Verification::Full);
    let any_backend_full = worked
        .iter()
        .filter(|a| a.verification == Verification::Full)
        .map(|a| a.backend)
        .collect::<Vec<_>>();
    let insecure_only: Vec<&&Attempt> = worked
        .iter()
        .filter(|a| a.verification != Verification::Full)
        .collect();

    if full_ok {
        let pick = worked
            .iter()
            .find(|a| a.verification == Verification::Full)
            .expect("checked");
        println!("Use the {} backend with {}.", pick.backend, pick.setting);
        println!("Certificate verification works, so keep it on.");
        if any_backend_full.contains(&"rustls") {
            println!("rustls is the better default here: no system TLS dependency.");
        } else {
            println!("Note rustls did not work: this host needs the operating system's");
            println!("TLS stack, so build with --features tls-native.");
        }
    } else if !insecure_only.is_empty() {
        let pick = insecure_only[0];
        println!("Handshakes succeed only with verification relaxed, so the transport");
        println!("is fine and the *certificate* is the problem. Working setting:");
        println!("  {} with {}", pick.backend, pick.setting);
        println!();
        println!("Fix the trust chain rather than shipping with checks off:");
        println!("  * 'chain only' worked but 'full' did not -> the certificate's name does");
        println!("    not match. Pass --servername with a name the certificate carries, or");
        println!("    keep Verification::SkipHostname deliberately.");
        println!("  * only 'none' worked -> the issuing CA is not trusted. Export it and");
        println!("    pass --cafile.");
    }
}

fn first_line(e: &str) -> String {
    e.lines().next().unwrap_or(e).trim().to_string()
}

fn dial(addr: &str) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no such address".to_string())?;
    let s = TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|e| e.to_string())?;
    Ok(s)
}

fn try_connect(connector: &dyn TlsConnector, addr: &str, name: &str) -> Result<String, String> {
    let socket = dial(addr)?;
    match connector.connect(socket, name) {
        Ok(stream) => {
            let proto = stream
                .protocol()
                .unwrap_or_else(|| "version not reported".into());
            let cipher = stream
                .cipher()
                .unwrap_or_else(|| "cipher not reported".into());
            Ok(format!("{proto}, {cipher}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(feature = "tls-rustls")]
fn probe_rustls(addr: &str, name: &str, cafile: Option<&str>, out: &mut Vec<Attempt>) {
    use tn3270::RustlsConfig;
    let base = || -> Result<RustlsConfig, String> {
        match cafile {
            Some(f) => RustlsConfig::with_ca_file(f).map_err(|e| e.to_string()),
            None => Ok(RustlsConfig::with_webpki_roots()),
        }
    };
    for (setting, pin) in [("TLS 1.2 and 1.3", false), ("TLS 1.2 only", true)] {
        for verification in [
            Verification::Full,
            Verification::SkipHostname,
            Verification::None,
        ] {
            let result = base().and_then(|c| {
                let mut c = c.verification(verification);
                if pin {
                    c = c.tls12_only();
                }
                try_connect(&c, addr, name)
            });
            out.push(Attempt {
                backend: "rustls",
                setting,
                verification,
                result,
            });
        }
    }
}

#[cfg(not(feature = "tls-rustls"))]
fn probe_rustls(_a: &str, _n: &str, _c: Option<&str>, out: &mut Vec<Attempt>) {
    out.push(Attempt {
        backend: "rustls",
        setting: "not compiled in",
        verification: Verification::Full,
        result: Err("rebuild with --features tls-rustls".into()),
    });
}

#[cfg(feature = "tls-native")]
fn probe_native(addr: &str, name: &str, cafile: Option<&str>, out: &mut Vec<Attempt>) {
    use tn3270::NativeTlsConfig;
    let base = || -> Result<NativeTlsConfig, String> {
        match cafile {
            Some(f) => NativeTlsConfig::with_ca_file(f).map_err(|e| e.to_string()),
            None => Ok(NativeTlsConfig::with_system_roots()),
        }
    };
    type Adjust = fn(NativeTlsConfig) -> NativeTlsConfig;
    let settings: [(&'static str, Adjust); 3] = [
        ("OS default versions", |c| c),
        ("TLS 1.2 only", |c| c.tls12_only()),
        ("TLS 1.0 and later", |c| c.allow_legacy_versions()),
    ];
    for (setting, adjust) in settings {
        for verification in [
            Verification::Full,
            Verification::SkipHostname,
            Verification::None,
        ] {
            let result = base()
                .map(|c| adjust(c).verification(verification))
                .and_then(|c| try_connect(&c, addr, name));
            out.push(Attempt {
                backend: "native-tls",
                setting,
                verification,
                result,
            });
        }
    }
}

#[cfg(not(feature = "tls-native"))]
fn probe_native(_a: &str, _n: &str, _c: Option<&str>, out: &mut Vec<Attempt>) {
    out.push(Attempt {
        backend: "native-tls",
        setting: "not compiled in",
        verification: Verification::Full,
        result: Err("rebuild with --features tls-native".into()),
    });
}
