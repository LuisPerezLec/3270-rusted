//! Replay recorded wire transcripts through the sans-IO core.
//!
//! These are the primary integration tests: they need no host, no network and
//! no Python, so they run anywhere the crate builds. Each transcript is a real
//! conversation captured against a TN3270E host, with the original socket chunk
//! boundaries preserved, so replaying one also exercises the decoder's handling
//! of records split across reads.
//!
//! Client output is compared byte for byte. That makes these snapshot tests: an
//! intentional change to the client's wire behaviour requires re-recording with
//! `examples/record_fixture.rs`, which is the point — the diff shows exactly
//! what changed on the wire.

use std::path::{Path, PathBuf};

use tn3270::ds::Aid;
use tn3270::negotiate::Mode;
use tn3270::{Event, Model, Session, SessionConfig};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(fixtures_dir())
        .expect("tests/fixtures must exist")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "trace"))
        .collect();
    paths.sort();
    paths
}

/// The outcome of replaying one transcript.
struct Replay {
    session: Session,
    events: Vec<Event>,
    /// Blocks of client output that were compared.
    client_blocks: usize,
}

fn replay(path: &Path) -> Replay {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let text = std::fs::read_to_string(path).expect("readable fixture");

    let mut config: Option<SessionConfig> = None;
    let mut model = Model::Model2;
    let mut tn3270e = true;
    let mut lu: Option<String> = None;
    let mut session: Option<Session> = None;
    let mut events = Vec::new();
    let mut client_blocks = 0usize;

    // Build the session lazily, once every directive has been seen.
    macro_rules! session {
        () => {{
            if session.is_none() {
                let mut c = SessionConfig::model(model);
                if let Some(lu) = &lu {
                    c = c.with_lu(lu.clone());
                }
                if !tn3270e {
                    c = c.without_tn3270e();
                }
                config = Some(c.clone());
                session = Some(Session::new(c));
            }
            session.as_mut().unwrap()
        }};
    }

    for (lineno, line) in text.lines().enumerate() {
        let lineno = lineno + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let where_ = format!("{name}:{lineno}");

        if let Some(rest) = line.strip_prefix('!') {
            let rest = rest.trim();
            let (word, arg) = rest.split_once(' ').unwrap_or((rest, ""));
            match word {
                "model" => {
                    assert!(session.is_none(), "{where_}: !model after data");
                    model = Model::from_number(arg.parse().expect("model number"))
                        .expect("model 2 to 5");
                }
                "tn3270e" => {
                    assert!(session.is_none(), "{where_}: !tn3270e after data");
                    tn3270e = arg == "true";
                }
                "lu" => {
                    assert!(session.is_none(), "{where_}: !lu after data");
                    lu = Some(arg.to_string());
                }
                "type" => session!()
                    .type_text(arg)
                    .unwrap_or_else(|e| panic!("{where_}: type {arg:?} failed: {e}")),
                "press" => {
                    let aid = parse_aid(arg).unwrap_or_else(|| panic!("{where_}: bad key {arg:?}"));
                    session!()
                        .press(aid)
                        .unwrap_or_else(|e| panic!("{where_}: press {arg} failed: {e}"));
                }
                other => panic!("{where_}: unknown directive {other:?}"),
            }
            continue;
        }

        let (dir, hex) = line.split_at(1);
        let bytes = decode_hex(hex.trim()).unwrap_or_else(|| panic!("{where_}: malformed hex"));
        match dir {
            "<" => {
                let s = session!();
                s.receive(&bytes);
                while let Some(event) = s.next_event() {
                    events.push(event);
                }
            }
            ">" => {
                let s = session!();
                let actual = s.take_output();
                client_blocks += 1;
                assert_eq!(
                    hexify(&actual),
                    hexify(&bytes),
                    "{where_}: client sent different bytes than were recorded.\n\
                     If this change was intended, re-record the fixture with\n\
                     cargo run --example record_fixture"
                );
            }
            other => panic!("{where_}: unknown direction {other:?}"),
        }
    }

    let session = session.expect("a fixture must contain at least one block");
    assert!(config.is_some());
    Replay {
        session,
        events,
        client_blocks,
    }
}

fn parse_aid(name: &str) -> Option<Aid> {
    match name {
        "Enter" => Some(Aid::Enter),
        "Clear" => Some(Aid::Clear),
        "SysReq" => Some(Aid::SysReq),
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

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hexify(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

// ============================================================ the tests ====

#[test]
fn fixtures_are_present() {
    // Guards the failure mode where the suite passes while testing nothing.
    let paths = fixture_paths();
    assert!(
        paths.len() >= 8,
        "expected the recorded transcripts to be committed, found {}",
        paths.len()
    );
}

#[test]
fn every_fixture_replays_byte_for_byte() {
    for path in fixture_paths() {
        let result = replay(&path);
        assert!(
            result.client_blocks > 0,
            "{}: no client output was compared",
            path.display()
        );
        assert!(
            result.session.is_connected(),
            "{}: negotiation did not complete",
            path.display()
        );
    }
}

#[test]
fn each_model_reaches_its_geometry_and_paints_the_logon_panel() {
    for (file, model, rows, cols) in [
        ("model2-tn3270e.trace", Model::Model2, 24, 80),
        ("model3-tn3270e.trace", Model::Model3, 32, 80),
        ("model4-tn3270e.trace", Model::Model4, 43, 80),
        ("model5-tn3270e.trace", Model::Model5, 27, 132),
    ] {
        let r = replay(&fixtures_dir().join(file));
        let screen = r.session.screen();
        assert_eq!(r.session.mode(), Mode::Tn3270e, "{file}");
        assert_eq!(r.session.device_type().model, model, "{file}");
        assert_eq!(
            (screen.rows(), screen.cols()),
            (rows, cols),
            "{file}: geometry, which arrives via the BIND image"
        );
        assert!(
            screen.find("TN3270 TEST HOST").is_some(),
            "{file}: banner missing from:\n{}",
            screen.text()
        );
        // The host echoes the geometry it believes, so this cross-checks our
        // parsing against an independent implementation's view.
        assert!(
            screen.find(&format!("{rows}x{cols}")).is_some(),
            "{file}: panel should state {rows}x{cols}"
        );
        assert_eq!(screen.cursor_row_col(), (9, 26), "{file}: Insert Cursor");
        assert!(!r.session.is_keyboard_locked(), "{file}: keyboard unlocked");
    }
}

#[test]
fn the_basic_path_negotiates_without_tn3270e() {
    let r = replay(&fixtures_dir().join("model2-basic.trace"));
    assert_eq!(r.session.mode(), Mode::Tn3270, "no TN3270E");
    assert_eq!(r.session.lu(), None, "no LU without TN3270E");
    assert!(r.session.functions().is_empty());
    assert!(r.session.screen().find("TN3270 TEST HOST").is_some());
    // The panel reports which dialect the host thinks it is speaking.
    assert!(r.session.screen().find("TN3270 ").is_some());
}

#[test]
fn an_explicitly_requested_lu_is_carried_through() {
    let r = replay(&fixtures_dir().join("model3-lu.trace"));
    assert_eq!(r.session.lu(), Some("MYLU42"));
    assert!(r.session.screen().find("LU=MYLU42").is_some());
}

#[test]
fn typed_input_round_trips_and_the_host_echoes_it() {
    let r = replay(&fixtures_dir().join("model2-logon.trace"));
    let screen = r.session.screen();
    assert!(
        screen.find("MAIN MENU").is_some(),
        "should reach the menu:\n{}",
        screen.text()
    );
    assert!(
        screen.find("Logged on as LUIS").is_some(),
        "the host must echo back the typed userid"
    );
}

#[test]
fn the_host_agrees_with_our_query_reply() {
    let r = replay(&fixtures_dir().join("model5-session-panel.trace"));
    let text = r.session.screen().text();
    assert!(text.contains("TN3270E"), "mode confirmed by the host");
    assert!(
        text.contains("27 rows x 132 cols"),
        "host must agree on the alternate size:\n{text}"
    );
    assert!(
        text.contains("UsableArea") || text.contains("ImplicitPartition"),
        "host must have parsed our Query Reply:\n{text}"
    );
}

#[test]
fn the_geometry_panel_fills_the_alternate_screen() {
    let r = replay(&fixtures_dir().join("model4-geometry.trace"));
    let screen = r.session.screen();
    assert_eq!(screen.rows(), 43);
    assert!(screen.find("ALTERNATE").is_some());
    // Corner markers prove addressing reaches the edges of the buffer.
    for marker in ["TL", "TR", "BL", "BR"] {
        assert!(screen.find(marker).is_some(), "missing {marker} marker");
    }
    // A Repeat to Address run.
    assert!(screen.find("*****").is_some(), "RA order did not fill");
}

#[test]
fn field_attributes_are_recovered_from_a_real_panel() {
    let r = replay(&fixtures_dir().join("model2-logon.trace"));
    let fields = r.session.screen().fields();
    assert!(fields.len() > 3, "the menu defines several fields");
    assert!(
        fields.iter().any(|f| f.attr.is_protected()),
        "protected labels"
    );
    assert!(
        fields.iter().any(|f| f.attr.is_input()),
        "an input field for the menu option"
    );
    assert!(
        fields.iter().any(|f| f.attr.is_numeric()),
        "the option field is numeric-only"
    );
}

#[test]
fn negotiation_events_arrive_in_a_sensible_order() {
    let r = replay(&fixtures_dir().join("model4-tn3270e.trace"));
    let connected = r
        .events
        .iter()
        .position(|e| matches!(e, Event::Connected { .. }))
        .expect("a Connected event");
    let unlocked = r
        .events
        .iter()
        .position(|e| matches!(e, Event::KeyboardUnlocked))
        .expect("a KeyboardUnlocked event");
    assert!(
        connected < unlocked,
        "the session must connect before the keyboard unlocks"
    );
    assert!(
        r.events.iter().any(|e| matches!(e, Event::ScreenUpdated)),
        "the screen must be reported as updated"
    );
    assert!(
        !r.events
            .iter()
            .any(|e| matches!(e, Event::ProtocolError(_))),
        "no protocol errors: {:?}",
        r.events
    );
}
