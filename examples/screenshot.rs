//! Connect to a host, print the screen, and optionally log on.
//!
//!     cargo run --example screenshot -- 127.0.0.1:3270
//!     cargo run --example screenshot -- 127.0.0.1:3270 --model 4 --logon LUIS
//!     cargo run --example screenshot -- 127.0.0.1:3270 --no-tn3270e

use std::time::Duration;

use tn3270::ds::Aid;
use tn3270::{Connection, Model, SessionConfig};

const TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:3270".into());
    let mut model = Model::Model2;
    let mut logon: Option<String> = None;
    let mut lu: Option<String> = None;
    let mut tn3270e = true;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--model" => {
                let n: u8 = args.next().unwrap_or_default().parse()?;
                model = Model::from_number(n).ok_or("model must be 2, 3, 4 or 5")?;
            }
            "--logon" => logon = args.next(),
            "--lu" => lu = args.next(),
            "--no-tn3270e" => tn3270e = false,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let mut config = SessionConfig::model(model);
    if let Some(lu) = lu {
        config = config.with_lu(lu);
    }
    if !tn3270e {
        config = config.without_tn3270e();
    }

    println!("connecting to {addr} as {}", config.negotiate.device_type);
    let mut conn = Connection::connect(&addr, config, TIMEOUT)?;

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

    conn.shutdown();
    Ok(())
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
