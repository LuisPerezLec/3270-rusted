//! Record a wire transcript against a live host, for replay in tests.
//!
//! Uses [`Session`] directly rather than the TCP transport, because that is
//! where the raw bytes are visible. It also doubles as a worked example of the
//! sans-IO API.
//!
//!     cargo run --example record_fixture -- 127.0.0.1:3270 \
//!         --model 4 --out tests/fixtures/model4-logon.trace --logon LUIS
//!
//! Transcripts are committed, so the test suite needs neither a host nor a
//! network. Re-record when the client's wire behaviour changes on purpose.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use tn3270::ds::Aid;
use tn3270::{Model, Session, SessionConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args
        .next()
        .ok_or("usage: record_fixture <host:port> [options]")?;
    let mut model = Model::Model2;
    let mut out_path = String::from("fixture.trace");
    let mut logon: Option<String> = None;
    let mut option: Option<String> = None;
    let mut lu: Option<String> = None;
    let mut tn3270e = true;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--model" => {
                model = Model::from_number(args.next().unwrap_or_default().parse()?)
                    .ok_or("model must be 2, 3, 4 or 5")?
            }
            "--out" => out_path = args.next().ok_or("--out needs a path")?,
            "--logon" => logon = args.next(),
            "--option" => option = args.next(),
            "--lu" => lu = args.next(),
            "--no-tn3270e" => tn3270e = false,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let mut config = SessionConfig::model(model);
    if let Some(lu) = &lu {
        config = config.clone().with_lu(lu.clone());
    }
    if !tn3270e {
        config = config.without_tn3270e();
    }

    let mut stream = TcpStream::connect(&addr)?;
    stream.set_nodelay(true)?;
    let mut session = Session::new(config);
    let mut transcript = Transcript::new(&addr, model, lu.as_deref(), tn3270e);

    // Anything the session wants to send before the host speaks.
    flush(&mut stream, &mut session, &mut transcript)?;

    // Phase 1: negotiate and take delivery of the first screen.
    pump_until(&mut stream, &mut session, &mut transcript, |s| {
        s.is_connected() && !s.is_keyboard_locked()
    })?;

    // Phase 2: optional typed input. The actions go into the transcript so a
    // replay performs them and must produce the same bytes.
    if let Some(user) = &logon {
        transcript.action(&format!("type {user}"));
        session.type_text(user)?;
        transcript.action("press Enter");
        session.press(Aid::Enter)?;
        flush(&mut stream, &mut session, &mut transcript)?;
        pump_until(&mut stream, &mut session, &mut transcript, |s| {
            !s.is_keyboard_locked()
        })?;
    }

    // Phase 3: optional menu selection.
    if let Some(opt) = &option {
        transcript.action(&format!("type {opt}"));
        session.type_text(opt)?;
        transcript.action("press Enter");
        session.press(Aid::Enter)?;
        flush(&mut stream, &mut session, &mut transcript)?;
        pump_until(&mut stream, &mut session, &mut transcript, |s| {
            !s.is_keyboard_locked()
        })?;
    }

    std::fs::write(&out_path, transcript.finish())?;
    println!("wrote {out_path}");
    println!(
        "final screen {}x{}",
        session.screen().rows(),
        session.screen().cols()
    );
    Ok(())
}

/// Send whatever the session has queued, recording it.
fn flush(
    stream: &mut TcpStream,
    session: &mut Session,
    transcript: &mut Transcript,
) -> std::io::Result<()> {
    let out = session.take_output();
    if !out.is_empty() {
        transcript.push('>', &out);
        stream.write_all(&out)?;
        stream.flush()?;
    }
    Ok(())
}

fn pump_until(
    stream: &mut TcpStream,
    session: &mut Session,
    transcript: &mut Transcript,
    done: impl Fn(&Session) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 8192];
    while !done(session) {
        if Instant::now() > deadline {
            return Err("timed out recording".into());
        }
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        match stream.read(&mut buf) {
            Ok(0) => return Err("host closed the connection".into()),
            Ok(n) => {
                // Record the real chunk boundary: replaying it exercises the
                // decoder's handling of records split across reads.
                transcript.push('<', &buf[..n]);
                session.receive(&buf[..n]);
                while let Some(event) = session.next_event() {
                    transcript.comment(&format!("event {event:?}"));
                }
                flush(stream, session, transcript)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Builds the transcript text.
struct Transcript {
    lines: Vec<String>,
}

impl Transcript {
    fn new(addr: &str, model: Model, lu: Option<&str>, tn3270e: bool) -> Transcript {
        let mut lines = vec![
            "# tn3270 wire transcript".to_string(),
            format!("# recorded against {addr}"),
            "#".to_string(),
            "# < bytes from the host, > bytes from the client.".to_string(),
            "# Each block is one real socket read or write, so chunk".to_string(),
            "# boundaries are preserved.".to_string(),
            "#".to_string(),
            format!("!model {}", model.number()),
            format!("!tn3270e {tn3270e}"),
        ];
        if let Some(lu) = lu {
            lines.push(format!("!lu {lu}"));
        }
        Transcript { lines }
    }

    fn comment(&mut self, text: &str) {
        self.lines.push(format!("# {text}"));
    }

    /// A client-side action, replayed verbatim by the test suite.
    fn action(&mut self, text: &str) {
        self.lines.push(format!("! {text}"));
    }

    fn push(&mut self, direction: char, data: &[u8]) {
        self.lines.push(format!("{direction} {}", hex(data)));
    }

    fn finish(self) -> String {
        let mut s = self.lines.join("\n");
        s.push('\n');
        s
    }
}

fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
