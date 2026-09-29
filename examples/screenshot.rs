//! Connect to a host, print the screen, and optionally drive it.
//!
//!     cargo run --example screenshot -- 127.0.0.1:3270
//!     cargo run --example screenshot -- 127.0.0.1:3270 --model 4 --logon LUIS
//!     cargo run --example screenshot -- 127.0.0.1:3270 --no-tn3270e
//!
//! `--do` runs one step and can be repeated. After every key it waits for the
//! host to unlock the keyboard, so steps stay in sync without sleeps:
//!
//!     cargo run --example screenshot -- 127.0.0.1:3272 \
//!         --do key:Enter --do "type:logon herc01" --do key:Enter --do show

use std::time::Duration;

use tn3270::ds::Aid;
use tn3270::{Connection, Model, SessionConfig};

const TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:3270".into());
    let mut model = Model::Model2;
    let mut device_override: Option<tn3270::DeviceType> = None;
    let mut logon: Option<String> = None;
    let mut lu: Option<String> = None;
    let mut tn3270e = true;
    let mut steps: Vec<String> = Vec::new();
    let mut tls = false;
    let mut cafile: Option<String> = None;
    let mut servername: Option<String> = None;
    let mut insecure = false;
    let mut tls12_only = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--model" => {
                let n: u8 = args.next().unwrap_or_default().parse()?;
                model = Model::from_number(n).ok_or("model must be 2, 3, 4 or 5")?;
            }
            "--logon" => logon = args.next(),
            "--lu" => lu = args.next(),
            "--no-tn3270e" => tn3270e = false,
            "--do" => steps.push(args.next().ok_or("--do needs a step")?),
            "--tls" => tls = true,
            "--cafile" => cafile = args.next(),
            "--servername" => servername = args.next(),
            "--insecure" => insecure = true,
            "--tls12-only" => tls12_only = true,
            "--device" => {
                let name = args.next().ok_or("--device needs a name")?;
                let dt = tn3270::DeviceType::parse(&name)
                    .ok_or_else(|| format!("{name} is not a device type this crate serves"))?;
                model = dt.model;
                device_override = Some(dt);
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let mut config = SessionConfig::model(model);
    if let Some(dt) = device_override {
        config.negotiate.device_type = dt;
    }
    if let Some(lu) = lu {
        config = config.with_lu(lu);
    }
    if !tn3270e {
        config = config.without_tn3270e();
    }

    println!("connecting to {addr} as {}", config.negotiate.device_type);
    let mut conn = if tls {
        connect_tls(&addr, config, cafile, servername, insecure, tls12_only)?
    } else {
        Connection::connect(&addr, config, TIMEOUT)?
    };

    for event in conn.take_events() {
        println!("  {event:?}");
    }
    println!(
        "negotiated {:?}  {}  LU={}  functions={:?}",
        conn.session().mode(),
        conn.session().device_type(),
        conn.session().lu().unwrap_or("(none)"),
        conn.session().functions(),
    );

    conn.wait_until_unlocked(TIMEOUT)?;
    show(&conn);

    if let Some(userid) = logon {
        println!("\ntyping {userid:?} and pressing Enter");
        conn.type_text(&userid)?;
        conn.press(Aid::Enter, TIMEOUT)?;
        show(&conn);
    }

    for step in &steps {
        run_step(&mut conn, step)?;
    }

    conn.shutdown();
    Ok(())
}

/// Run one `--do` step.
fn run_step(conn: &mut Connection, step: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (verb, arg) = step.split_once(':').unwrap_or((step, ""));
    match verb {
        "show" => show(conn),
        "settle" => {
            let ms: u64 = if arg.is_empty() { 500 } else { arg.parse()? };
            println!("\n-- settling: waiting for {ms}ms of host silence");
            conn.wait_for_quiet(Duration::from_millis(ms), TIMEOUT)?;
            for event in conn.take_events() {
                if matches!(event, tn3270::Event::ProtocolError(_)) {
                    println!("   !! {event:?}");
                }
            }
        }
        "fields" => {
            let screen = conn.screen();
            println!(
                "\n-- fields ({} total, formatted={})",
                screen.fields().len(),
                screen.is_formatted()
            );
            for f in screen.fields() {
                let (r, c) = screen.row_col(f.start);
                if f.len == 0 {
                    continue;
                }
                println!(
                    "   ({r:2},{c:3}) len {:3} {}{}{}{} {:?}",
                    f.len,
                    if f.attr.is_protected() {
                        "prot "
                    } else {
                        "INPUT"
                    },
                    if f.attr.is_numeric() { " num" } else { "" },
                    if f.attr.is_hidden() { " hidden" } else { "" },
                    if f.attr.is_modified() { " MDT" } else { "" },
                    screen.field_text(&f).chars().take(28).collect::<String>(),
                );
            }
        }
        "cursorinfo" => {
            let screen = conn.screen();
            let (r, c) = screen.cursor_row_col();
            println!(
                "\n-- cursor ({r},{c}) addr {} writable={} attr={:?}",
                screen.cursor(),
                screen.is_writable(screen.cursor()),
                screen.field_attr(screen.cursor()),
            );
        }
        "type" => {
            println!("\n-- type {arg:?}");
            conn.type_text(arg)?;
        }
        "cursor" => {
            let (r, c) = arg.split_once(',').ok_or("cursor:ROW,COL")?;
            let (r, c) = (r.trim().parse()?, c.trim().parse()?);
            println!("\n-- cursor to ({r},{c})");
            conn.set_cursor(r, c);
        }
        "tab" => {
            println!("\n-- tab");
            conn.tab();
        }
        "key" => {
            let aid = parse_key(arg).ok_or_else(|| format!("unknown key {arg:?}"))?;
            println!("\n-- press {aid}, waiting for the host to unlock");
            conn.press(aid, TIMEOUT)?;
            for event in conn.take_events() {
                // Protocol errors are the ones that matter: they mean part of a
                // record was discarded.
                if matches!(event, tn3270::Event::ProtocolError(_)) {
                    println!("   !! {event:?}");
                }
            }
            show(conn);
        }
        other => return Err(format!("unknown step {other:?}").into()),
    }
    Ok(())
}

fn parse_key(name: &str) -> Option<Aid> {
    match name.to_ascii_uppercase().as_str() {
        "ENTER" => Some(Aid::Enter),
        "CLEAR" => Some(Aid::Clear),
        "SYSREQ" => Some(Aid::SysReq),
        other => {
            if let Some(n) = other.strip_prefix("PF") {
                Some(Aid::Pf(n.parse().ok()?))
            } else if let Some(n) = other.strip_prefix("PA") {
                Some(Aid::Pa(n.parse().ok()?))
            } else {
                None
            }
        }
    }
}

#[cfg(feature = "tls")]
fn connect_tls(
    addr: &str,
    config: SessionConfig,
    cafile: Option<String>,
    servername: Option<String>,
    insecure: bool,
    tls12_only: bool,
) -> Result<Connection, Box<dyn std::error::Error>> {
    use tn3270::TlsConfig;
    let mut tls = match (&cafile, insecure) {
        (Some(path), _) => TlsConfig::with_ca_file(path)?,
        (None, true) => TlsConfig::insecure(),
        (None, false) => TlsConfig::with_webpki_roots(),
    };
    if tls12_only {
        tls = tls.tls12_only();
    }
    // The name the certificate must match. Defaults to the dialled host, which
    // fails for an IP unless the certificate carries an IP SAN.
    let name = servername.unwrap_or_else(|| {
        addr.rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| addr.to_string())
    });
    println!("  TLS, verifying against {name:?}");
    let conn = Connection::connect_tls(addr, &name, config, &tls, TIMEOUT)?;
    if let Some((version, suite)) = conn.tls_info() {
        println!("  negotiated {version:?} with {:?}", suite.suite());
    }
    Ok(conn)
}

#[cfg(not(feature = "tls"))]
fn connect_tls(
    _addr: &str,
    _config: SessionConfig,
    _cafile: Option<String>,
    _servername: Option<String>,
    _insecure: bool,
    _tls12_only: bool,
) -> Result<Connection, Box<dyn std::error::Error>> {
    Err("this build has no TLS; rebuild with --features tls".into())
}

fn show(conn: &Connection) {
    let screen = conn.screen();
    let (rows, cols) = (screen.rows(), screen.cols());
    let (cr, cc) = screen.cursor_row_col();
    println!("\n{rows}x{cols}, cursor at ({cr},{cc})");
    println!("+{}+", "-".repeat(usize::from(cols)));
    for row in 1..=rows {
        println!("|{}|", screen.row_text(row));
    }
    println!("+{}+", "-".repeat(usize::from(cols)));
}
