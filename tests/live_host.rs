//! Optional tests against a *live* TN3270E host.
//!
//! Every test here is `#[ignore]`d, so a plain `cargo test` reports them as
//! ignored rather than quietly passing. The recorded transcripts in
//! `tests/replay.rs` are the tests that run everywhere; these exist to prove
//! the handshake still works against a real peer, and to re-validate before
//! re-recording fixtures.
//!
//! Run them with either:
//!
//! ```text
//! # against an already-running host
//! TN3270_LIVE_HOST=127.0.0.1:3270 cargo test --test live_host -- --ignored
//!
//! # or let the suite start the Python test host, if it is on this machine
//! TN3270_TEST_HOST_DIR=../s3270 cargo test --test live_host -- --ignored
//! ```
//!
//! When neither is set these **fail** rather than skip: asking for them
//! explicitly and getting silence would be the worst outcome.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as OsCommand, Stdio};
use std::time::Duration;

use tn3270::ds::Aid;
use tn3270::negotiate::{Function, Mode};
use tn3270::{Connection, Event, Model, SessionConfig};

const TIMEOUT: Duration = Duration::from_secs(15);

/// Where the Python test host lives, from `TN3270_TEST_HOST_DIR`.
///
/// Deliberately not guessed from a sibling directory: this crate ships on its
/// own, and a path that silently fails to resolve would turn these tests into
/// no-ops.
fn host_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("TN3270_TEST_HOST_DIR")?;
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    if path.join("mainframe/__main__.py").exists() {
        Some(path)
    } else {
        panic!(
            "TN3270_TEST_HOST_DIR points at {}, which has no mainframe/__main__.py",
            path.display()
        )
    }
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    l.local_addr().expect("local address").port()
}

/// A running host process, killed on drop.
struct TestHost {
    child: Child,
    port: u16,
}

impl TestHost {
    /// Start the host, or return `None` if it is not available here.
    fn start(extra: &[&str]) -> Option<TestHost> {
        TestHost::start_inner(extra, None)
    }

    /// `await_port` is the listener to wait for. The host prints one
    /// "listening on" line per listener, so waiting for the first would race a
    /// TLS port that is bound second.
    fn start_inner(extra: &[&str], await_port: Option<u16>) -> Option<TestHost> {
        let dir = host_dir()?;
        let port = free_port();
        let mut cmd = OsCommand::new("python3");
        cmd.current_dir(&dir)
            .args(["-m", "mainframe", "--no-color"])
            .args(["--port", &port.to_string()]);
        if await_port.is_none() {
            cmd.args(["--tls-port", "0"]);
        }
        cmd.args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().ok()?;

        // The host prints a "listening on" line once the socket is bound;
        // waiting for it beats sleeping and guessing.
        let wanted = await_port.unwrap_or(port).to_string();
        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        for _ in 0..40 {
            line.clear();
            if reader.read_line(&mut line).ok()? == 0 {
                break;
            }
            if line.contains("listening on") && line.contains(&wanted) {
                // Keep draining in the background so the pipe never fills.
                std::thread::spawn(move || {
                    let mut sink = String::new();
                    while reader.read_line(&mut sink).unwrap_or(0) > 0 {
                        sink.clear();
                    }
                });
                return Some(TestHost { child, port });
            }
        }
        let _ = child.kill();
        None
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Start the host with a TLS listener on `tls_port` as well.
    #[cfg(feature = "tls")]
    fn start_with_tls(tls_port: u16) -> Option<TestHost> {
        TestHost::start_inner(&["--tls-port", &tls_port.to_string()], Some(tls_port))
    }
}

impl Drop for TestHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A host to test against: either an address given in the environment, or one
/// this function starts.
enum Target {
    Live(String),
    Spawned(TestHost),
}

impl Target {
    fn addr(&self) -> String {
        match self {
            Target::Live(addr) => addr.clone(),
            Target::Spawned(host) => host.addr(),
        }
    }
}

/// Resolve a target, or fail with an actionable message.
///
/// `extra` host arguments only apply when this function starts the host, so a
/// test needing them is skipped against a pre-running one.
fn target(extra: &[&str]) -> Target {
    if let Ok(addr) = std::env::var("TN3270_LIVE_HOST") {
        // A test needing custom host arguments cannot use a host it did not
        // start. Fail rather than return quietly: a test that cannot run must
        // not report success.
        assert!(
            extra.is_empty(),
            "this test needs a host started with {extra:?}, which \
             TN3270_LIVE_HOST cannot provide. Use TN3270_TEST_HOST_DIR instead."
        );
        return Target::Live(addr);
    }
    if host_dir().is_some() {
        let host = TestHost::start(extra).expect("the Python test host should start");
        return Target::Spawned(host);
    }
    panic!(
        "no host to test against. Set TN3270_LIVE_HOST=<addr> for a running \
         host, or TN3270_TEST_HOST_DIR=<path> to start the Python test host."
    );
}

/// Run `body` against a host.
fn with_host(extra: &[&str], body: impl FnOnce(&Target)) {
    body(&target(extra));
}

fn connect(host: &Target, config: SessionConfig) -> Connection {
    let mut conn = Connection::connect(host.addr(), config, TIMEOUT).expect("connects");
    conn.wait_until_unlocked(TIMEOUT)
        .expect("host paints a screen");
    conn
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn every_model_negotiates_and_renders() {
    with_host(&[], |host| {
        for (model, rows, cols) in [
            (Model::Model2, 24, 80),
            (Model::Model3, 32, 80),
            (Model::Model4, 43, 80),
            (Model::Model5, 27, 132),
        ] {
            let conn = connect(host, SessionConfig::model(model));
            let screen = conn.screen();

            assert_eq!(conn.session().mode(), Mode::Tn3270e, "{model}");
            assert_eq!(
                (screen.rows(), screen.cols()),
                (rows, cols),
                "{model} geometry, which arrives via the BIND image"
            );
            assert!(
                screen.find("TN3270 TEST HOST").is_some(),
                "{model} should render the banner, got:\n{}",
                screen.text()
            );
            // The host echoes the negotiated geometry back onto the panel, so
            // this cross-checks our parsing against the host's own view.
            let expected = format!("{rows}x{cols}");
            assert!(
                screen.find(&expected).is_some(),
                "{model} panel should mention {expected}"
            );
            // An Insert Cursor order put the cursor on the userid field.
            assert_eq!(screen.cursor_row_col(), (9, 26), "{model} cursor");
        }
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn the_basic_tn3270_path_works_when_tn3270e_is_declined() {
    with_host(&[], |host| {
        let conn = connect(host, SessionConfig::model(Model::Model2).without_tn3270e());
        assert_eq!(conn.session().mode(), Mode::Tn3270);
        assert_eq!(conn.session().lu(), None, "no LU without TN3270E");
        assert!(conn.session().functions().is_empty());
        assert!(conn.screen().find("TN3270 TEST HOST").is_some());
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn a_requested_lu_is_honoured() {
    with_host(&[], |host| {
        let conn = connect(host, SessionConfig::model(Model::Model2).with_lu("MYLU42"));
        assert_eq!(conn.session().lu(), Some("MYLU42"));
        assert!(conn.screen().find("LU=MYLU42").is_some());
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn bind_image_and_query_reply_are_exchanged() {
    with_host(&[], |host| {
        let conn = connect(host, SessionConfig::model(Model::Model4));
        assert!(
            conn.session().functions().contains(&Function::BindImage),
            "BIND-IMAGE should be negotiated"
        );
        // The host only paints after it receives our Query Reply, so a drawn
        // screen proves the exchange happened. Its session panel reports what
        // it parsed from us, which we check below.
        assert_eq!(conn.screen().rows(), 43);
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn typing_and_enter_round_trip_through_the_host() {
    with_host(&[], |host| {
        let mut conn = connect(host, SessionConfig::model(Model::Model2));
        conn.type_text("LUIS")
            .expect("the cursor is in an input field");
        conn.press(Aid::Enter, TIMEOUT).expect("host accepts Enter");

        let screen = conn.screen();
        assert!(
            screen.find("MAIN MENU").is_some(),
            "should reach the menu, got:\n{}",
            screen.text()
        );
        assert!(
            screen.find("Logged on as LUIS").is_some(),
            "the host should echo back what we typed"
        );
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn the_host_reports_our_query_reply_correctly() {
    with_host(&[], |host| {
        let mut conn = connect(host, SessionConfig::model(Model::Model5));
        conn.type_text("TEST").unwrap();
        conn.press(Aid::Enter, TIMEOUT).unwrap();
        // Menu option 4 is the session-details panel.
        conn.type_text("4").unwrap();
        conn.press(Aid::Enter, TIMEOUT).unwrap();

        let text = conn.screen().text();
        assert!(text.contains("TN3270E"), "panel should confirm the mode");
        assert!(
            text.contains("27 rows x 132 cols"),
            "host should agree on the alternate size:\n{text}"
        );
        assert!(
            text.contains("UsableArea") || text.contains("ImplicitPartition"),
            "host should have parsed our Query Reply:\n{text}"
        );
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn pf_keys_navigate_and_short_read_keys_are_accepted() {
    with_host(&[], |host| {
        let mut conn = connect(host, SessionConfig::model(Model::Model2));
        conn.type_text("TEST").unwrap();
        conn.press(Aid::Enter, TIMEOUT).unwrap();
        assert!(conn.screen().find("MAIN MENU").is_some());

        // PF1 opens help.
        conn.press(Aid::Pf(1), TIMEOUT).unwrap();
        assert!(
            conn.screen().find("HELP").is_some(),
            "PF1 should open help:\n{}",
            conn.screen().text()
        );
        // PF3 returns.
        conn.press(Aid::Pf(3), TIMEOUT).unwrap();
        assert!(conn.screen().find("MAIN MENU").is_some());

        // CLEAR is a short read: the AID byte alone, no cursor, no fields.
        conn.press(Aid::Clear, TIMEOUT).unwrap();
        assert!(
            conn.screen().find("MAIN MENU").is_some(),
            "the host redraws after CLEAR"
        );
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn the_alternate_and_primary_screens_switch_on_demand() {
    with_host(&[], |host| {
        let mut conn = connect(host, SessionConfig::model(Model::Model4));
        conn.type_text("TEST").unwrap();
        conn.press(Aid::Enter, TIMEOUT).unwrap();
        // Panel 2 draws over the whole alternate screen.
        conn.type_text("2").unwrap();
        conn.press(Aid::Enter, TIMEOUT).unwrap();
        assert_eq!(conn.screen().rows(), 43, "alternate size");
        assert!(conn.screen().find("ALTERNATE").is_some());

        // PF4 switches the host to Erase/Write, the primary 24x80 screen.
        conn.press(Aid::Pf(4), TIMEOUT).unwrap();
        assert_eq!(
            conn.screen().rows(),
            24,
            "Erase/Write must resize us back to the primary screen"
        );
        assert!(conn.screen().find("PRIMARY").is_some());

        // And back again.
        conn.press(Aid::Pf(4), TIMEOUT).unwrap();
        assert_eq!(conn.screen().rows(), 43);
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn a_rejected_device_type_is_surfaced() {
    // The host is pinned to model 5; ask for model 2 and expect a refusal.
    with_host(&["--only-model", "5"], |host| {
        let result = Connection::connect(
            host.addr(),
            SessionConfig::model(Model::Model2),
            Duration::from_secs(5),
        );
        match result {
            Err(_) => {} // never reached ready, which is correct
            Ok(mut conn) => {
                let rejected = conn
                    .take_events()
                    .iter()
                    .any(|e| matches!(e, Event::DeviceRejected(_)));
                assert!(rejected, "a pinned host must reject the wrong model");
            }
        }
    });
}

#[test]
#[ignore = "needs a live host; see the module docs"]
fn field_attributes_survive_the_round_trip() {
    with_host(&[], |host| {
        let mut conn = connect(host, SessionConfig::model(Model::Model2));
        conn.type_text("TEST").unwrap();
        conn.press(Aid::Enter, TIMEOUT).unwrap();
        // Panel 1 is the field playground.
        conn.type_text("1").unwrap();
        conn.press(Aid::Enter, TIMEOUT).unwrap();

        let screen = conn.screen();
        let fields = screen.fields();
        assert!(fields.len() > 5, "the playground defines many fields");
        assert!(
            fields.iter().any(|f| f.attr.is_hidden()),
            "it includes a non-display password field"
        );
        assert!(
            fields.iter().any(|f| f.attr.is_numeric()),
            "and a numeric-only field"
        );
        assert!(
            fields.iter().any(|f| f.attr.is_modified()),
            "and one with its modified tag preset"
        );
        assert!(
            fields.iter().any(|f| f.attr.is_protected()),
            "and protected labels"
        );
    });
}

// ---------------------------------------------------------------- TLS ------

/// TLS tests need the Python host's generated certificates, so they use
/// `TN3270_TEST_HOST_DIR` to find them and a host started with a TLS port.
#[cfg(feature = "tls")]
mod tls {
    use super::*;
    use tn3270::TlsConfig;

    fn ca_path() -> PathBuf {
        host_dir()
            .expect("TLS tests need TN3270_TEST_HOST_DIR")
            .join("certs/ca.crt")
    }

    /// Start the host with a TLS listener and return its TLS port.
    fn tls_host() -> (TestHost, u16) {
        let port = free_port();
        let host = TestHost::start_with_tls(port).expect("host with TLS starts");
        (host, port)
    }

    #[test]
    #[ignore = "needs a live host; see the module docs"]
    fn tls12_with_the_hosts_ca_completes_a_session() {
        if std::env::var_os("TN3270_TEST_HOST_DIR").is_none() {
            panic!("set TN3270_TEST_HOST_DIR so the generated CA can be found");
        }
        let (_host, port) = tls_host();
        let tls = TlsConfig::with_ca_file(ca_path())
            .expect("the CA file should parse")
            .tls12_only();
        let mut conn = Connection::connect_tls(
            format!("127.0.0.1:{port}"),
            "localhost",
            SessionConfig::model(Model::Model3),
            &tls,
            TIMEOUT,
        )
        .expect("TLS connects");
        conn.wait_until_unlocked(TIMEOUT).expect("host paints");

        let (version, _suite) = conn.tls_info().expect("an encrypted connection");
        assert_eq!(
            version,
            rustls::ProtocolVersion::TLSv1_2,
            "the host is pinned to 1.2 and so are we"
        );
        assert!(conn.screen().find("TN3270 TEST HOST").is_some());
        assert!(conn.screen().find("TLS1.2").is_some(), "host reports TLS");
    }

    #[test]
    #[ignore = "needs a live host; see the module docs"]
    fn an_untrusted_certificate_is_refused() {
        if std::env::var_os("TN3270_TEST_HOST_DIR").is_none() {
            panic!("set TN3270_TEST_HOST_DIR so the generated CA can be found");
        }
        let (_host, port) = tls_host();
        // Public roots did not sign this certificate.
        let tls = TlsConfig::with_webpki_roots();
        let err = Connection::connect_tls(
            format!("127.0.0.1:{port}"),
            "localhost",
            SessionConfig::model(Model::Model2),
            &tls,
            TIMEOUT,
        )
        .expect_err("an unknown issuer must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("UnknownIssuer") || msg.contains("certificate"),
            "unhelpful error: {msg}"
        );
    }

    #[test]
    #[ignore = "needs a live host; see the module docs"]
    fn a_certificate_name_mismatch_is_refused() {
        if std::env::var_os("TN3270_TEST_HOST_DIR").is_none() {
            panic!("set TN3270_TEST_HOST_DIR so the generated CA can be found");
        }
        let (_host, port) = tls_host();
        let tls = TlsConfig::with_ca_file(ca_path()).expect("CA parses");
        let err = Connection::connect_tls(
            format!("127.0.0.1:{port}"),
            "wrong.example.com",
            SessionConfig::model(Model::Model2),
            &tls,
            TIMEOUT,
        )
        .expect_err("a name mismatch must be refused");
        assert!(
            err.to_string().contains("not valid for name"),
            "the error should name the problem: {err}"
        );
    }

    #[test]
    #[ignore = "needs a live host; see the module docs"]
    fn insecure_mode_connects_without_any_trust_anchor() {
        let (_host, port) = tls_host();
        let tls = TlsConfig::insecure();
        let mut conn = Connection::connect_tls(
            format!("127.0.0.1:{port}"),
            "127.0.0.1",
            SessionConfig::model(Model::Model2),
            &tls,
            TIMEOUT,
        )
        .expect("insecure mode ignores the trust chain");
        conn.wait_until_unlocked(TIMEOUT).expect("host paints");
        assert!(conn.screen().find("TN3270 TEST HOST").is_some());
    }
}
