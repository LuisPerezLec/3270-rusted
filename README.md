# tn3270

An IBM 3270 terminal emulator and automation library for Rust, with no C
dependencies.

The protocol core has **no dependencies at all** and is *sans-IO*: it never
touches a socket. Bytes go in, events and outbound bytes come out. A blocking
TCP transport is layered on top behind the default `tcp` feature.

```rust
use std::time::Duration;
use tn3270::{Connection, Model, SessionConfig};
use tn3270::ds::Aid;

let timeout = Duration::from_secs(10);
let mut conn = Connection::connect(
    "mvs.example.com:23",
    SessionConfig::model(Model::Model4),
    timeout,
)?;

conn.wait_until_unlocked(timeout)?;      // the host has finished painting
conn.type_text("MYUSER")?;
conn.press(Aid::Enter, timeout)?;        // sends, then waits for the reply

println!("{}", conn.screen().text());
assert!(conn.screen().find("MAIN MENU").is_some());
```

## Why sans-IO

Keeping the protocol free of I/O buys three things that matter for this problem:

* a recorded byte stream is a complete test fixture, so the test suite needs no
  mainframe and no network;
* the same core can drive blocking, async or in-process transports;
* the logic can be compared against a reference implementation by feeding both
  the identical stream, which is how the details below were settled.

## Status

Early, but the protocol path is real and tested end to end against an
independent host implementation.

**Working**

| Area | Detail |
|---|---|
| Telnet framing | IAC escaping, `IAC EOR` records, subnegotiation, records split across reads |
| TN3270E | RFC 2355: `DEVICE-TYPE`, `FUNCTIONS` including counter-offers, `REJECT` with reason, the 5-byte header, responses |
| Basic TN3270 | RFC 1576 fallback: `TERMINAL-TYPE` + `BINARY` + `EOR`, no header |
| Models | 2, 3, 4 and 5, with primary and alternate screen sizes kept distinct |
| LU | optional; requested or host-assigned |
| BIND image | parsed, including the descriptor byte that decides whether the alternate size is honoured |
| Query Reply | answered automatically; hosts that wait for it would otherwise hang |
| Data stream | `W`, `EW`, `EWA`, `EAU`, `WSF`, the read commands, and every order: `SBA`, `SF`, `SFE`, `SA`, `MF`, `IC`, `PT`, `RA`, `EUA`, `GE` |
| Inbound | AID, cursor, modified fields, short reads, `SYSREQ`, Read Buffer |
| Screen model | fields, basic and extended attributes, colour, highlighting, cursor, text search |
| Code pages | cp037, cp273, cp500, cp1026, cp1140 |
| TLS | 1.2 and 1.3 via `rustls`, with an internal-CA trust store, optional 1.2 pinning, and IP-SAN verification |

**Not yet**

* **The full keyboard state machine.** `type_text` writes at the cursor, sets
  the modified-data-tag and refuses protected and non-numeric input. Insert
  mode, auto-skip, field overflow and `Dup`/`FieldMark` are not implemented.
* **NVT (line mode) emulation.** Line-mode text is reported as
  `Event::NvtText` so a session manager is *visible*, but not driven.
* File transfer (`IND$FILE`), printer sessions, DBCS, async transports.

## Timing, which is the hard part

There is no "end of screen" marker in the 3270 protocol. A host may paint one
logical panel with several writes, so deciding when it has finished is the
usual source of flaky automation, and a sleep is not the answer.

The real signal is the keyboard-restore bit in the Write Control Character.
Sending an AID locks the keyboard; the host unlocks it when it is done.
`wait_until_unlocked` waits for exactly that, and `press` does it for you.
`Session::is_keyboard_locked` exposes the same state to other transports.

That is necessary but not always sufficient. Some hosts send a **second screen
unprompted** — a banner followed by a logon panel, a status line repainted a
moment later — and acting on the first one means typing into a screen that is
about to be replaced. `wait_for_quiet(idle, timeout)` waits for the
conversation to go quiet instead:

```rust
// MVS 3.8j under Hercules sends its banner, then a logon panel, unprompted.
conn.wait_for_quiet(Duration::from_millis(500), timeout)?;
```

Use `wait_until_unlocked` for a request/response panel, and `wait_for_quiet`
when the host volunteers screens. The probe below reports which case you are in.

## Layers

| Module | Responsibility |
|---|---|
| `ebcdic` | code page conversion, tables generated from the reference mappings |
| `telnet` | framing: IAC escaping, records, subnegotiation |
| `negotiate` | TN3270E and basic TN3270 negotiation, BIND images, headers |
| `ds` | the data stream: orders, attributes, addressing, inbound records, structured fields |
| `screen` | the screen buffer, fields, cursor, geometry |
| `session` | the sans-IO session tying them together |
| `transport` | blocking TCP, with the `wait_*` primitives |

Code page tables are generated rather than transcribed:

```bash
python3 tools/gen_codepages.py > src/ebcdic/tables.rs
```

The output is `#[rustfmt::skip]`-marked and idempotent, so regenerating never
fights `cargo fmt`. Adding a code page is a one-line change to `PAGES`.

Constant names follow x3270's `3270ds.h`, so this can be read side by side with
the reference implementation.

## Details that are easy to get wrong

Each of these was verified against the reference rather than assumed, and each
has a test naming it:

* **A field's data starts one column after its attribute.** The attribute byte
  occupies a visible cell and renders blank. Off-by-one here misaligns
  everything.
* **`CLEAR` and `PA1`-`PA3` send the AID byte alone** — no cursor address, no
  fields. Sending a cursor with them is wrong.
* **`SYSREQ` is not an AID record**: it sends `SOH % / STX`.
* **Nulls inside a modified field are omitted, not sent as spaces.** A field
  holding `AB` followed by nulls goes out as two bytes.
* **Repeat to Address with a target equal to the current address fills the
  entire buffer**, because the reference uses a `do`/`while`.
* **Program Tab nulls the rest of the field only when it follows data**, not
  when it follows a command or another order.
* **BIND image byte 24 decides everything.** `0x7F` honours a distinct
  alternate size; `0x7E` forces it equal to the default, silently clamping a
  model 4 back to 24x80.
* **Non-display fields render blank** but keep their content in the buffer, so
  `row_text` hides a password while `field_bytes` still returns it.
* **Never offer `DO BINARY` or `DO EOR` unsolicited.** Sending them straight
  after the terminal type is legal telnet, and a hand-written host tolerates it,
  but Hercules running MVS 3.8j stops negotiating and the session hangs with no
  error. Only ever answer what the host offers.
* **A host may paint more than one screen per turn.** Waiting only for the
  keyboard to unlock lands you on the first of them. See the timing section.
* **A record split across TCP reads must not be flushed early.** The decoder
  emits a record only on `IAC EOR`; pending bytes are drained as line-mode text
  only before 3270 framing begins.

## Tests

```bash
cargo test
```

Self-contained: no host, no network, no Python. 115 tests run, and CI runs
nothing else. Verified by copying the tree somewhere isolated and running the
suite there.

| Suite | What it covers |
|---|---|
| unit (103) | every protocol layer in isolation: code pages, addressing, attributes, orders, inbound encoding, negotiation, framing, TLS configuration |
| `tests/replay.rs` (10) | recorded wire transcripts replayed through the sans-IO core |
| doc tests (2) | the examples in the crate docs compile |
| `tests/live_host.rs` (14) | optional, against a real host including TLS — `#[ignore]`d by default |

### Recorded transcripts

`tests/fixtures/*.trace` are real conversations captured against a TN3270E
host: negotiation, BIND image, Query Reply exchange, typed input, menu
navigation, for models 2 to 5 and both dialects. The original socket chunk
boundaries are preserved, so replaying one also exercises the decoder's handling
of records split across reads.

They are human-readable and diffable:

```text
!model 2
!tn3270e true
< fffd28                                      # host: DO TN3270E
> fffb28                                      # client: WILL TN3270E
< fffa280802fff0                              # host: SEND DEVICE-TYPE
> fffa28020749424d2d333237392d322d45fff0      # client: REQUEST IBM-3279-2-E
! type LUIS
! press Enter
```

Client output is compared **byte for byte**, which makes these snapshot tests. A
deliberate change to the client's wire behaviour needs the fixture re-recorded,
and the diff then shows exactly what moved on the wire:

```bash
cargo run --example record_fixture -- 127.0.0.1:3270 \
    --model 4 --logon MYUSER --out tests/fixtures/model4-logon.trace
```

What transcripts cannot cover is behaviour the recorded host never exhibits — a
VTAM session manager in line mode, an unusual code page, or a host that demands
`ALWAYS-RESPONSE`. Those need a live peer.

### Optional live-host tests

Every test in `tests/live_host.rs` is `#[ignore]`d, so a plain `cargo test`
reports them as *ignored* rather than quietly passing. Opt in explicitly:

```bash
# against a host already running
TN3270_LIVE_HOST=127.0.0.1:3270 cargo test --test live_host -- --ignored

# or let the suite start the Python test host
TN3270_TEST_HOST_DIR=../s3270 cargo test --test live_host -- --ignored
```

With neither set they **fail** rather than skip, and a test that needs a
specially configured host fails when only `TN3270_LIVE_HOST` is given. A test
that cannot run must never report success.

## License

MIT OR Apache-2.0.
