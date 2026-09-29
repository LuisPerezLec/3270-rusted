//! Pre-flight probe: dump a negotiation frame by frame and report what the
//! host actually does.
//!
//! Run this against a host *before* writing code against it. It sends no AID,
//! so it cannot press a key or disturb anything on the host side, and its
//! verdict maps directly onto `SessionConfig`.
//!
//! This is the tool to reach for when a host does not behave as expected. It
//! prints every telnet frame in both directions, the decoded 3270 command
//! stream, and — if negotiation never completes — exactly which preconditions
//! are still missing.
//!
//!     cargo run --example trace -- 127.0.0.1:3270
//!     cargo run --example trace -- mvs.example.com:23 --device IBM-3278-2-E
//!     cargo run --example trace -- 127.0.0.1:3272 --no-tn3270e --seconds 8

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use tn3270::negotiate::{Config, DeviceType, Mode};
use tn3270::telnet::{self, Decoder, Frame};
use tn3270::{Event, Session, SessionConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().ok_or("usage: trace <host:port> [options]")?;
    let mut device = DeviceType::default();
    let mut lu = None;
    let mut tn3270e = true;
    let mut seconds = 10u64;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--device" => {
                let name = args.next().ok_or("--device needs a name")?;
                device = DeviceType::parse(&name)
                    .ok_or_else(|| format!("{name} is not a device type this crate serves"))?;
            }
            "--lu" => lu = args.next(),
            "--no-tn3270e" => tn3270e = false,
            "--seconds" => seconds = args.next().ok_or("--seconds needs a number")?.parse()?,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let config = SessionConfig {
        negotiate: Config {
            device_type: device,
            lu: lu.clone(),
            allow_tn3270e: tn3270e,
            ..Config::default()
        },
        ..SessionConfig::default()
    };

    println!("connecting to {addr}");
    println!(
        "  requesting {device}{}",
        match &lu {
            Some(lu) => format!(", LU {lu}"),
            None => String::new(),
        }
    );
    println!(
        "  TN3270E {}\n",
        if tn3270e { "offered" } else { "refused" }
    );

    let mut stream = TcpStream::connect(&addr)?;
    stream.set_nodelay(true)?;
    let mut session = Session::new(config);
    // A second decoder over the same bytes, purely so frames can be printed
    // without reaching into the session.
    let mut view = Decoder::new();

    send(&mut stream, &mut session)?;

    let mut nvt_text: Vec<String> = Vec::new();
    let mut extra_screens = 0usize;
    let lu_requested = lu.is_some();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut buf = [0u8; 8192];
    while Instant::now() < deadline {
        stream.set_read_timeout(Some(Duration::from_millis(400)))?;
        let n = match stream.read(&mut buf) {
            Ok(0) => {
                println!("<- host closed the connection");
                break;
            }
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        };

        for frame in view.decode(&buf[..n])? {
            println!("<- {}", describe(&frame));
        }
        if !view.pending().is_empty() {
            println!(
                "<- {} pending byte(s), no IAC EOR yet",
                view.pending().len()
            );
        }

        session.receive(&buf[..n]);
        while let Some(event) = session.next_event() {
            println!("   * {event:?}");
            match &event {
                Event::NvtText(t) | Event::SscpText(t) => nvt_text.push(t.clone()),
                Event::KeyboardUnlocked => extra_screens += 1,
                _ => {}
            }
        }
        send(&mut stream, &mut session)?;
    }

    let screen = session.screen();
    println!("\n{}", "=".repeat(68));
    println!("  verdict after {seconds}s");
    println!("{}", "=".repeat(68));
    match session.mode() {
        Mode::Tn3270e => {
            println!("  TN3270E         NEGOTIATED");
            println!("                  every record carries the 5-byte header");
        }
        Mode::Tn3270 => {
            println!("  TN3270E         not used -- basic TN3270 (RFC 1576)");
            println!("                  records carry no header");
        }
        Mode::Nvt => println!("  TN3270E         negotiation never completed"),
    }
    println!("  Device type     {}", session.device_type());
    println!(
        "  LU              {}",
        session.lu().unwrap_or("(none assigned)")
    );
    println!("  Functions       {:?}", session.functions());
    println!("  Screen          {}x{}", screen.rows(), screen.cols());
    if nvt_text.is_empty() {
        println!("  Line-mode text  none: the host went straight to 3270");
    } else {
        println!("  Line-mode text  the host sent text before 3270 mode:");
        for line in nvt_text.iter().take(4) {
            println!("                  {line:?}");
        }
        println!("                  a session manager may need driving first");
    }
    println!(
        "  Unsolicited     {}",
        if extra_screens > 1 {
            format!("{extra_screens} screens arrived; use wait_for_quiet, not wait_until_unlocked")
        } else {
            "one screen, so wait_until_unlocked is enough".to_string()
        }
    );

    println!("\n  SessionConfig for this host:");
    println!(
        "      let config = SessionConfig::model(Model::Model{})",
        session.device_type().model.number()
    );
    if session.mode() == Mode::Nvt {
        println!("          // negotiation did not finish; see the hints below");
    }
    if let Some(lu) = session.lu() {
        if lu_requested {
            println!("          .with_lu(\"{lu}\")   // you asked for this name");
        } else {
            println!("          // LU {lu} was assigned by the host; no need to request one");
        }
    }
    if session.mode() == Mode::Tn3270 && tn3270e {
        println!("          // the host never offered TN3270E, so the fallback is in use;");
        println!("          // leaving allow_tn3270e on costs nothing");
    }
    println!("      ;");

    println!("{}", "=".repeat(68));

    if !session.is_connected() {
        println!("\nNegotiation did not complete. For the basic TN3270 path all of");
        println!("these must hold, and the host drives most of them:");
        println!("  * the host sent SB TERMINAL-TYPE SEND and we answered");
        println!("  * DO BINARY and DO EOR were received (so we perform them)");
        println!("  * WILL BINARY and WILL EOR were received (so the host does)");
        println!("Compare against the frames above to see which is missing.");
    } else if screen.text().trim().is_empty() {
        println!("\nNegotiated, but the host has painted nothing yet.");
    } else {
        println!("\nFirst screen:");
        for row in 1..=screen.rows() {
            let line = screen.row_text(row);
            if !line.trim().is_empty() {
                println!("  {line}");
            }
        }
    }
    Ok(())
}

fn send(stream: &mut TcpStream, session: &mut Session) -> std::io::Result<()> {
    let out = session.take_output();
    if out.is_empty() {
        return Ok(());
    }
    let mut echo = Decoder::new();
    if let Ok(frames) = echo.decode(&out) {
        for frame in frames {
            println!("-> {}", describe(&frame));
        }
    }
    stream.write_all(&out)?;
    stream.flush()
}

fn describe(frame: &Frame) -> String {
    match frame {
        Frame::Command { verb, option } => {
            format!("{verb} {}", telnet::option_name(*option))
        }
        Frame::Subnegotiation(body) => {
            let opt = body.first().copied().unwrap_or(0);
            format!(
                "SB {} {}",
                telnet::option_name(opt),
                printable(&body[1.min(body.len())..])
            )
        }
        Frame::Record(data) => {
            let head = data
                .first()
                .and_then(|&b| tn3270::Command::from_byte(b))
                .map(|c| c.name().to_string())
                .unwrap_or_else(|| format!("0x{:02X}", data.first().copied().unwrap_or(0)));
            format!("record, {} bytes, {head}", data.len())
        }
        Frame::Signal(b) => format!("signal 0x{b:02X}"),
    }
}

/// Render a subnegotiation body: ASCII where it is printable, hex otherwise.
fn printable(body: &[u8]) -> String {
    let mut out = String::new();
    for &b in body {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        } else {
            out.push_str(&format!("<{b:02X}>"));
        }
    }
    out
}
