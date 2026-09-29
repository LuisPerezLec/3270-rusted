# Connecting to a real host

The 3270 protocol is a specification, but hosts differ in which *optional*
parts they use. Almost every surprise when pointing a new client at a real
mainframe comes from one of those options, not from the data stream itself.

This is the short path from "no idea what that host does" to working
automation, ordered so the surprises arrive early and cheaply.

---

## Step 0 — Using it without publishing

Publishing to crates.io is optional and unrelated to using the crate. Pick
whichever of these fits the network.

**Nothing at all.** The examples run in place, straight from a clone:

```bash
git clone <repo> && cd 3270-rusted
cargo run --example trace -- mvs.example.com:23
```

With default features this pulls **no dependencies whatsoever** — the protocol
core has none — so a `cargo build` here downloads nothing.

**A path dependency**, for an application beside the clone:

```toml
# myapp/Cargo.toml, with the clone as a sibling directory
[dependencies]
tn3270 = { path = "../3270-rusted" }
# or, when TLS is needed:
# tn3270 = { path = "../3270-rusted", features = ["tls"] }
```

**A git dependency**, when an internal git host is reachable:

```toml
[dependencies]
tn3270 = { git = "https://git.internal.example/team/3270-rusted.git", tag = "v0.1.0" }
```

**Fully offline**, if the registry is not reachable at all. Vendor once on a
machine that can download, then copy the tree across:

```bash
cargo vendor ../vendor > .cargo/config.toml
cargo build --offline
```

Two things to know before enabling `tls`:

* it pulls in rustls and its dependencies — 27 crates, against **zero** without
  it — so prove plain-text connectivity first and add TLS after;
* rustls's `ring` backend compiles C and assembly, so a C compiler must be
  present. On Linux `cc` is needed to link any Rust binary anyway, so this is
  rarely a new requirement, but it is worth checking before blaming the crate.

A path dependency has to be replaced with a version or git reference if the
application is ever published itself. Nothing else about this needs revisiting.

---

## Step 1 — Probe before writing any code

```bash
cargo run --example trace -- mvs.example.com:23
```

This prints every telnet frame in both directions and ends with a verdict. It
**sends no AID**, so it cannot press a key or disturb anything on the host.

Add `--tls --cafile corp-ca.pem` if the port is TLS, `--lu MYLU01` to request a
specific LU, and `--seconds 15` on a slow link.

Read the verdict like this:

| Verdict line | Meaning | Action |
|---|---|---|
| `TN3270E  NEGOTIATED` | RFC 2355; records carry a 5-byte header | nothing: the default config handles it |
| `TN3270E  not used` | RFC 1576 basic; no header | nothing: the fallback is automatic |
| `TN3270E  negotiation never completed` | something stalled | see *Negotiation stalls* below |
| `LU  (none assigned)` | the host assigns nothing | do not request one |
| `LU  SOMENAME` | assigned or honoured | request it only if it was requested |
| `Line-mode text  none` | straight to 3270 | nothing |
| `Line-mode text  the host sent text…` | a session manager speaks first | see *Line-mode text* below |
| `Unsolicited  one screen` | one screen per turn | `wait_until_unlocked` is enough |
| `Unsolicited  N screens arrived` | the host volunteers screens | use `wait_for_quiet` |

The verdict ends with a paste-ready `SessionConfig` for that host.

---

## Step 2 — Explore the host without writing code

```bash
cargo run --example screenshot -- mvs.example.com:23 \
    --do settle:800 \
    --do "type:logon myuser" --do key:Enter --do settle:800 \
    --do fields --do cursorinfo
```

Steps, repeatable and run in order:

| Step | Effect |
|---|---|
| `settle:MS` | wait for `MS` milliseconds of host silence |
| `key:Enter`, `key:PF3`, `key:PA1`, `key:Clear` | press it, then wait for the unlock |
| `type:TEXT` | type at the cursor |
| `cursor:ROW,COL` | move the cursor (1-based) |
| `tab` | next unprotected field |
| `show` | print the screen |
| `fields` | every field with its attributes |
| `cursorinfo` | cursor position, whether it is writable, its attribute |

This is the fastest way to learn a screen flow before committing it to code.

---

## Step 3 — The first program

```rust
use std::time::Duration;
use tn3270::ds::Aid;
use tn3270::{Connection, Model, SessionConfig};

const T: Duration = Duration::from_secs(15);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SessionConfig::model(Model::Model2);   // from the probe
    let mut conn = Connection::connect("mvs.example.com:23", config, T)?;

    // Wait for the host to finish painting. Use wait_for_quiet instead if the
    // probe reported more than one screen per turn.
    conn.wait_until_unlocked(T)?;

    // Always assert which screen this is before typing. Acting on an
    // unexpected screen is the single most common cause of a broken script.
    assert!(conn.screen().find("LOGON").is_some(), "unexpected screen:\n{}", conn.screen().text());

    conn.set_cursor(9, 26);              // be explicit; do not trust the cursor
    conn.type_text("MYUSER")?;
    conn.press(Aid::Enter, T)?;          // sends, then waits for the unlock

    println!("{}", conn.screen().text());
    Ok(())
}
```

Over TLS, replace the connect call:

```rust
use tn3270::TlsConfig;
let tls = TlsConfig::with_ca_file("corp-ca.pem")?.tls12_only();
let mut conn = Connection::connect_tls(
    "mvs.example.com:992",
    "mvs.example.com",       // the name on the certificate, not the dial address
    config, &tls, T,
)?;
```

Requires `--features tls`.

---

## The traps, in the order they bite

**1. Waiting on the wrong thing.** There is no "end of screen" marker in 3270.
`wait_until_unlocked` returns on the first screen the host unlocks; if the host
then sends another one unprompted, the script types into a screen that is about
to be replaced. Symptom: input silently ignored, or a host error like
`INPUT NOT RECOGNIZED`. Fix: `conn.wait_for_quiet(Duration::from_millis(500), T)`.
Never fix it with a plain sleep — it will be either too short or too slow.

**2. A field's data starts one column after its attribute.** The attribute byte
occupies a visible cell and renders blank. `Field::attr_addr` is the attribute,
`Field::start` is the first data position. Setting the cursor to the attribute
byte makes typing fail.

**3. Typing into a protected field.** `type_text` returns
`ActionError::ProtectedField { row, col }` rather than corrupting the screen.
Usually it means trap 1 or 2, not a protected field that should be writable.

**4. The wrong code page.** `cp037` is right for US English hosts only. Wrong
code page shows as correct-looking layout with mangled accented or national
characters. Fix: `SessionConfig::model(m).with_code_page(CodePage::lookup("cp273").unwrap())`.
Compiled in: cp037, cp273, cp500, cp1026, cp1140.

**5. Line-mode text before 3270 starts.** Some hosts show a VTAM session
manager or a `USSMSG` in telnet line mode first. It arrives as
`Event::NvtText`, and the screen stays empty until it is dealt with. This crate
reports such text but does not drive a line-mode dialogue, so a host that
requires one needs its front end handled another way.

**6. The TLS name is not the dial address.** `connect_tls` takes the
certificate name separately, so a host reached by IP can still be verified
against the name on its certificate. On a mismatch, rustls lists the
certificate's valid names in the error — read it rather than reaching for
`insecure()`.

**7. `CLEAR` and `PA1`–`PA3` send the AID byte alone.** No cursor, no fields.
That is correct and handled; just do not expect field data to reach the host on
those keys.

**8. Sessions outlive the TCP connection.** Dropping a connection can leave the
session logged on, and the next logon is then refused (`userid in use`,
`waiting for reconnect`). Log off properly at the end of a script.

---

## Negotiation stalls

If the verdict says negotiation never completed, compare the frames the probe
printed against the checklist it prints. For the basic path all of these must
happen, and the host drives most of them:

* the host sends `SB TERMINAL-TYPE SEND` and the client answers
* `DO BINARY` and `DO EOR` arrive
* `WILL BINARY` and `WILL EOR` arrive

A host that goes silent immediately after the terminal type is usually
objecting to something the client volunteered. This crate deliberately sends
nothing unsolicited, because doing so hangs Hercules; if a fork adds an
unsolicited `DO`, that is the first thing to suspect.

---

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `Timeout` from `connect` | negotiation never completed | run the probe; see *Negotiation stalls* |
| Connects, screen stays empty | host is waiting for something, or sent line-mode text | check for `Event::NvtText`; try a longer `settle` |
| `INPUT NOT RECOGNIZED`, or input ignored | acted on a screen that was then replaced | `wait_for_quiet` |
| `ActionError::ProtectedField` | cursor on an attribute byte or wrong screen | `cursorinfo`, then `set_cursor` explicitly |
| `ActionError::KeyboardLocked` | the host has not finished | wait for `Event::KeyboardUnlocked` |
| Layout right, accents wrong | wrong code page | set the code page |
| `TLS handshake failed: UnknownIssuer` | the CA is not trusted | `TlsConfig::with_ca_file` with the internal CA |
| `certificate not valid for name` | wrong certificate name | use the name the error lists |
| `Event::ProtocolError("host addressed cell N…")` | host wrote for the alternate screen while on the primary | the negotiated model is smaller than the host assumes; check the probe's model |
| `userid in use` on logon | a previous session is still on | log off at the end of scripts |

---

## What to record, and what not to

On a restricted network, the useful output is **protocol facts, not session
captures**. The probe's verdict is a dozen lines of metadata — negotiated mode,
device type, functions, geometry, whether screens arrive unsolicited — and those
facts are enough to reproduce the host's behaviour locally:

```bash
# the local test host can be told to behave like the real one
./run.sh --tn3270e off --only-model 2
```

Screen content is a different matter: it is application data. Use `--no-screen`
on the Python prober, or simply do not copy `show` output off the network.
