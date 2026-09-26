//! Applying an outbound data stream to the screen.
//!
//! Order semantics here follow x3270's `ctlr_write`, including the two that
//! are easy to get wrong:
//!
//! * **Repeat to Address** fills with a `do`/`while`, so a target equal to the
//!   current address fills the *entire* buffer rather than nothing.
//! * **Program Tab** nulls the rest of the current field only when it follows
//!   data, not when it follows a command or another order.

use super::addr;
use super::attr::{ExtType, Extended, FieldAttr};
use super::{Command, Order, Wcc};
use crate::screen::Screen;

/// What an outbound record turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub command: Command,
    pub wcc: Option<Wcc>,
    /// The host sent an Insert Cursor order.
    pub cursor_set: bool,
    /// Structured fields carried by a Write Structured Field command.
    pub structured_fields: Vec<Vec<u8>>,
}

impl Parsed {
    /// True when the host unlocked the keyboard, meaning input is allowed.
    pub fn unlocks_keyboard(&self) -> bool {
        self.wcc.map(Wcc::keyboard_restore).unwrap_or(false)
    }
}

/// Why an outbound record could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The record had no command byte.
    Empty,
    /// The first byte was not a recognised command.
    UnknownCommand(u8),
    /// An order ran off the end of the record.
    Truncated(&'static str),
    /// An order addressed a cell outside the current screen.
    ///
    /// This is what a host hits when it writes for the alternate screen size
    /// while the terminal is still on the primary one.
    AddressOutOfRange { addr: u16, max: u16 },
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Empty => f.write_str("empty record"),
            ParseError::UnknownCommand(b) => write!(f, "unknown command 0x{b:02X}"),
            ParseError::Truncated(what) => write!(f, "record truncated: {what}"),
            ParseError::AddressOutOfRange { addr, max } => {
                write!(f, "address {addr} exceeds the screen maximum {max}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Apply one host-to-terminal record to `screen`.
pub fn apply(screen: &mut Screen, data: &[u8]) -> Result<Parsed, ParseError> {
    let &cmd_byte = data.first().ok_or(ParseError::Empty)?;
    let command = Command::from_byte(cmd_byte).ok_or(ParseError::UnknownCommand(cmd_byte))?;

    let mut parsed = Parsed {
        command,
        wcc: None,
        cursor_set: false,
        structured_fields: Vec::new(),
    };

    if command == Command::WriteStructuredField {
        parsed.structured_fields = split_structured_fields(&data[1..]);
        return Ok(parsed);
    }

    if command.is_read() {
        // A read changes nothing; the session builds the reply.
        return Ok(parsed);
    }

    if command == Command::EraseAllUnprotected {
        erase_all_unprotected(screen);
        return Ok(parsed);
    }

    let mut i = 1;
    if command.has_wcc() {
        let &wcc_byte = data.get(1).ok_or(ParseError::Truncated("missing WCC"))?;
        let wcc = Wcc(wcc_byte);
        parsed.wcc = Some(wcc);
        i = 2;

        if command == Command::EraseWrite {
            screen.select_primary();
        } else if command == Command::EraseWriteAlternate {
            screen.select_alternate();
        }
        if wcc.sound_alarm() {
            screen.alarm = true;
        }
        if wcc.reset_mdt() {
            screen.reset_all_modified();
        }
    }

    let size = screen.size();
    let max = size - 1;
    let mut cur = 0u16;
    // Character-level attributes set by Set Attribute, applied to data that
    // follows until changed.
    let mut pending = Extended::default();
    // x3270's `last_cmd`: true just after a command or order, false after a
    // data character. Program Tab consults it.
    let mut last_cmd = true;
    let mut last_zpt = false;
    let mut graphic_escape = false;

    while i < data.len() {
        let byte = data[i];
        let order = Order::from_byte(byte);

        // A Graphic Escape applies to the single byte that follows, which may
        // otherwise look like an order.
        if graphic_escape {
            write_byte(screen, cur, byte, pending, true);
            cur = screen.inc(cur);
            graphic_escape = false;
            last_cmd = false;
            last_zpt = false;
            i += 1;
            continue;
        }

        match order {
            Some(Order::Sba) => {
                let (hi, lo) = two(data, i + 1, "SBA address")?;
                cur = check(addr::decode(hi, lo), max)?;
                i += 3;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Sf) => {
                let a = *data
                    .get(i + 1)
                    .ok_or(ParseError::Truncated("SF attribute"))?;
                start_field(screen, cur, FieldAttr(a), Extended::default());
                cur = screen.inc(cur);
                pending = Extended::default();
                i += 2;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Sfe) => {
                let count = *data
                    .get(i + 1)
                    .ok_or(ParseError::Truncated("SFE pair count"))?
                    as usize;
                let mut attr = FieldAttr::UNPROTECTED;
                let mut ext = Extended::default();
                let mut j = i + 2;
                for _ in 0..count {
                    let (t, v) = two(data, j, "SFE attribute pair")?;
                    match ExtType::from_byte(t) {
                        ExtType::Basic => attr = FieldAttr(v),
                        kind => ext.apply(kind, v),
                    }
                    j += 2;
                }
                start_field(screen, cur, attr, ext);
                cur = screen.inc(cur);
                pending = Extended::default();
                i = j;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Sa) => {
                let (t, v) = two(data, i + 1, "SA attribute pair")?;
                pending.apply(ExtType::from_byte(t), v);
                i += 3;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Mf) => {
                let count = *data
                    .get(i + 1)
                    .ok_or(ParseError::Truncated("MF pair count"))?
                    as usize;
                let mut j = i + 2;
                for _ in 0..count {
                    let (t, v) = two(data, j, "MF attribute pair")?;
                    match ExtType::from_byte(t) {
                        ExtType::Basic => {
                            if let Some(f) = screen.cell_mut(cur).field.as_mut() {
                                *f = FieldAttr(v);
                            }
                        }
                        kind => screen.cell_mut(cur).extended.apply(kind, v),
                    }
                    j += 2;
                }
                cur = screen.inc(cur);
                i = j;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Ic) => {
                screen.set_cursor(cur);
                parsed.cursor_set = true;
                i += 1;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Pt) => {
                cur = program_tab(screen, cur, &mut last_cmd, &mut last_zpt);
                i += 1;
            }
            Some(Order::Ra) => {
                let (hi, lo) = two(data, i + 1, "RA address")?;
                let target = check(addr::decode(hi, lo), max)?;
                let mut k = i + 3;
                let mut ge = false;
                if data.get(k) == Some(&Order::Ge.as_byte()) {
                    ge = true;
                    k += 1;
                }
                let fill = *data.get(k).ok_or(ParseError::Truncated("RA character"))?;
                // A do/while: target == cur fills the whole buffer.
                loop {
                    write_byte(screen, cur, fill, pending, ge);
                    cur = screen.inc(cur);
                    if cur == target {
                        break;
                    }
                }
                i = k + 1;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Eua) => {
                let (hi, lo) = two(data, i + 1, "EUA address")?;
                let target = check(addr::decode(hi, lo), max)?;
                let mut a = cur;
                loop {
                    if screen.is_writable(a) {
                        let cell = screen.cell_mut(a);
                        cell.byte = 0x00;
                        cell.extended = Extended::default();
                        cell.graphic_escape = false;
                    }
                    a = screen.inc(a);
                    if a == target {
                        break;
                    }
                }
                i += 3;
                last_cmd = true;
                last_zpt = false;
            }
            Some(Order::Ge) => {
                graphic_escape = true;
                i += 1;
            }
            None => {
                // An ordinary data byte.
                write_byte(screen, cur, byte, pending, false);
                cur = screen.inc(cur);
                i += 1;
                last_cmd = false;
                last_zpt = false;
            }
        }
    }

    Ok(parsed)
}

fn two(data: &[u8], at: usize, what: &'static str) -> Result<(u8, u8), ParseError> {
    match (data.get(at), data.get(at + 1)) {
        (Some(&a), Some(&b)) => Ok((a, b)),
        _ => Err(ParseError::Truncated(what)),
    }
}

fn check(addr: u16, max: u16) -> Result<u16, ParseError> {
    if addr > max {
        Err(ParseError::AddressOutOfRange { addr, max })
    } else {
        Ok(addr)
    }
}

fn write_byte(screen: &mut Screen, at: u16, byte: u8, ext: Extended, ge: bool) {
    let cell = screen.cell_mut(at);
    cell.byte = byte;
    // Writing data over a field attribute turns the position into data.
    cell.field = None;
    cell.extended = ext;
    cell.graphic_escape = ge;
}

fn start_field(screen: &mut Screen, at: u16, attr: FieldAttr, ext: Extended) {
    let cell = screen.cell_mut(at);
    cell.byte = 0x00;
    cell.field = Some(attr);
    cell.extended = ext;
    cell.graphic_escape = false;
}

/// Program Tab, following x3270's rules exactly.
fn program_tab(screen: &mut Screen, cur: u16, last_cmd: &mut bool, last_zpt: &mut bool) -> u16 {
    // On the attribute byte of an unprotected field, just step over it.
    if let Some(attr) = screen.cell(cur).field {
        if !attr.is_protected() {
            *last_zpt = false;
            *last_cmd = true;
            return screen.inc(cur);
        }
    }

    let mut target = next_unprotected(screen, cur);
    if target < cur {
        target = 0;
    }

    // Null the rest of the current field, but only when this PT followed
    // data rather than a command or order.
    if !*last_cmd || *last_zpt {
        let mut a = cur;
        while a != target && !screen.cell(a).is_field_start() {
            let cell = screen.cell_mut(a);
            cell.byte = 0x00;
            cell.extended = Extended::default();
            cell.graphic_escape = false;
            a = screen.inc(a);
        }
        *last_zpt = target == 0;
    } else {
        *last_zpt = false;
    }
    *last_cmd = true;
    target
}

/// First data position of the next unprotected field after `from`.
fn next_unprotected(screen: &Screen, from: u16) -> u16 {
    let size = screen.size();
    let mut a = screen.inc(from);
    for _ in 0..size {
        let prev = screen.dec(a);
        if let Some(attr) = screen.cell(prev).field {
            if !attr.is_protected() && !screen.cell(a).is_field_start() {
                return a;
            }
        }
        a = screen.inc(a);
    }
    0
}

fn erase_all_unprotected(screen: &mut Screen) {
    let size = screen.size();
    for a in 0..size {
        if screen.is_writable(a) {
            let cell = screen.cell_mut(a);
            cell.byte = 0x00;
            cell.extended = Extended::default();
            cell.graphic_escape = false;
        }
    }
    screen.reset_all_modified();
    // The cursor homes to the first unprotected position.
    let home = (0..size).find(|&a| screen.is_writable(a)).unwrap_or(0);
    screen.set_cursor(home);
}

/// Split a run of length-prefixed structured fields.
///
/// The length counts itself, and a length of zero means "the rest of the
/// record".
pub fn split_structured_fields(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = usize::from(u16::from_be_bytes([data[i], data[i + 1]]));
        if len == 0 {
            out.push(data[i + 2..].to_vec());
            break;
        }
        if len < 2 || i + len > data.len() {
            out.push(data[i..].to_vec());
            break;
        }
        out.push(data[i + 2..i + len].to_vec());
        i += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ds::attr::{Color, Highlight, Intensity};
    use crate::screen::Model;

    fn sba(addr: u16) -> Vec<u8> {
        let [hi, lo] = addr::encode(addr);
        vec![Order::Sba.as_byte(), hi, lo]
    }

    #[test]
    fn erase_write_selects_the_primary_screen() {
        let mut s = Screen::new(Model::Model4);
        assert_eq!(s.rows(), 43);
        apply(&mut s, &[Command::EraseWrite.as_byte(), 0xC3]).unwrap();
        assert_eq!((s.rows(), s.cols()), (24, 80));
    }

    #[test]
    fn erase_write_alternate_selects_the_model_screen() {
        let mut s = Screen::primary(Model::Model5);
        assert_eq!((s.rows(), s.cols()), (24, 80));
        apply(&mut s, &[Command::EraseWriteAlternate.as_byte(), 0xC3]).unwrap();
        assert_eq!((s.rows(), s.cols()), (27, 132));
    }

    #[test]
    fn an_address_past_the_screen_is_rejected() {
        // Exactly the failure a host hits by writing alternate-sized output
        // to a primary screen.
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::Write.as_byte(), 0xC3];
        rec.extend(sba(3200));
        assert_eq!(
            apply(&mut s, &rec),
            Err(ParseError::AddressOutOfRange {
                addr: 3200,
                max: 1919
            })
        );
    }

    #[test]
    fn a_field_and_its_text_land_where_the_host_meant() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        rec.extend([Order::Sf.as_byte(), 0xE0]); // protected
        rec.extend([0xC8, 0x89]); // "Hi"
        apply(&mut s, &rec).unwrap();

        assert!(s.cell(0).is_field_start());
        assert_eq!(s.cell(1).byte, 0xC8);
        assert_eq!(s.row_text(1).trim_end(), " Hi");
        assert!(s.fields()[0].attr.is_protected());
    }

    #[test]
    fn repeat_to_address_fills_up_to_but_not_including_the_target() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        let [hi, lo] = addr::encode(5);
        rec.extend([Order::Ra.as_byte(), hi, lo, 0x5C]); // '*'
        apply(&mut s, &rec).unwrap();
        assert_eq!(s.text_at(1, 1, 6), "***** ", "fills 0..4, leaves 5 alone");
    }

    #[test]
    fn repeat_to_the_current_address_fills_the_whole_buffer() {
        // The do/while in the reference: this is not a no-op.
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        let [hi, lo] = addr::encode(0);
        rec.extend([Order::Ra.as_byte(), hi, lo, 0x5C]);
        apply(&mut s, &rec).unwrap();
        assert!(
            s.cells().iter().all(|c| c.byte == 0x5C),
            "every cell should be filled"
        );
    }

    #[test]
    fn extended_attributes_attach_to_the_field() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        rec.extend([
            Order::Sfe.as_byte(),
            3,
            ExtType::Basic.as_byte(),
            0xE0,
            ExtType::Foreground.as_byte(),
            Color::Yellow.as_byte(),
            ExtType::Highlighting.as_byte(),
            Highlight::Underscore.as_byte(),
        ]);
        rec.push(0xC1);
        apply(&mut s, &rec).unwrap();

        let cell = s.cell(0);
        assert!(cell.is_field_start());
        assert_eq!(cell.extended.foreground, Color::Yellow);
        assert_eq!(cell.extended.highlight, Highlight::Underscore);
        assert!(cell.field.unwrap().is_protected());
    }

    #[test]
    fn set_attribute_applies_to_following_characters_only() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        rec.push(0xC1); // 'A' with no attributes
        rec.extend([
            Order::Sa.as_byte(),
            ExtType::Foreground.as_byte(),
            Color::Red.as_byte(),
        ]);
        rec.push(0xC2); // 'B' in red
        apply(&mut s, &rec).unwrap();
        assert_eq!(s.cell(0).extended.foreground, Color::Default);
        assert_eq!(s.cell(1).extended.foreground, Color::Red);
    }

    #[test]
    fn insert_cursor_positions_the_cursor() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(s.addr_of(5, 10)));
        rec.push(Order::Ic.as_byte());
        let parsed = apply(&mut s, &rec).unwrap();
        assert!(parsed.cursor_set);
        assert_eq!(s.cursor_row_col(), (5, 10));
    }

    #[test]
    fn the_wcc_controls_alarm_unlock_and_mdt_reset() {
        let mut s = Screen::primary(Model::Model2);
        s.cell_mut(0).field = Some(FieldAttr::new(false, false, Intensity::Normal, true));
        assert!(s.fields()[0].attr.is_modified());

        let parsed = apply(&mut s, &[Command::Write.as_byte(), 0xC7]).unwrap();
        assert!(parsed.unlocks_keyboard());
        assert!(s.alarm, "0xC7 has the alarm bit set");
        assert!(
            !s.fields()[0].attr.is_modified(),
            "reset-MDT bit cleared it"
        );

        let mut s2 = Screen::primary(Model::Model2);
        let quiet = apply(&mut s2, &[Command::Write.as_byte(), 0xC0]).unwrap();
        assert!(!quiet.unlocks_keyboard());
        assert!(!s2.alarm);
    }

    #[test]
    fn program_tab_nulls_forward_only_when_it_follows_data() {
        // An unprotected field at 0 holding "ABCDEFGH", another at 20.
        // Re-enter at address 3, overwrite one byte, then Program Tab.
        let build = |trailing: &[u8]| {
            let mut s = Screen::primary(Model::Model2);
            let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
            rec.extend(sba(0));
            rec.extend([Order::Sf.as_byte(), 0xC0]);
            rec.extend([0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8]); // ABCDEFGH
            rec.extend(sba(20));
            rec.extend([Order::Sf.as_byte(), 0xC0]);
            rec.extend(sba(3));
            rec.extend(trailing);
            apply(&mut s, &rec).unwrap();
            s
        };

        // Baseline: the field holds ABCDEFGH at columns 2..9.
        assert_eq!(build(&[]).text_at(1, 2, 8), "ABCDEFGH");

        // PT immediately after SBA, which is an order: no nulling at all.
        let after_order = build(&[Order::Pt.as_byte()]);
        assert_eq!(
            after_order.text_at(1, 2, 8),
            "ABCDEFGH",
            "PT after an order only moves the address"
        );

        // PT after a data byte: everything from the current address to the end
        // of the field is nulled. Bytes written *before* the current address
        // survive, which is what "the remainder of the field" means.
        let after_data = build(&[0xE7, Order::Pt.as_byte()]); // write 'X' at 3
        assert_eq!(
            after_data.text_at(1, 2, 8),
            "ABX     ",
            "PT after data nulls forward from the current address only"
        );
    }

    #[test]
    fn program_tab_steps_over_an_unprotected_attribute_byte() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        rec.extend([Order::Sf.as_byte(), 0xC0]); // unprotected field at 0
        rec.extend(sba(0)); // back onto the attribute byte
        rec.extend([Order::Pt.as_byte()]);
        rec.push(0xE9); // 'Z' should land at address 1
        apply(&mut s, &rec).unwrap();
        assert_eq!(s.cell(1).byte, 0xE9, "PT advanced exactly one position");
    }

    #[test]
    fn erase_all_unprotected_spares_protected_fields() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        rec.extend([Order::Sf.as_byte(), 0xE0]); // protected
        rec.extend([0xD3, 0xC1, 0xC2]); // "LAB"
        rec.extend(sba(10));
        rec.extend([Order::Sf.as_byte(), 0xC1]); // unprotected, MDT preset
        rec.extend([0xE5, 0xC1]); // "VA"
        apply(&mut s, &rec).unwrap();
        assert_eq!(s.text_at(1, 2, 3), "LAB");
        assert_eq!(s.text_at(1, 12, 2), "VA");

        apply(&mut s, &[Command::EraseAllUnprotected.as_byte()]).unwrap();
        assert_eq!(s.text_at(1, 2, 3), "LAB", "protected text survives");
        assert_eq!(s.text_at(1, 12, 2), "  ", "unprotected text is erased");
        assert!(s.fields().iter().all(|f| !f.attr.is_modified()));
    }

    #[test]
    fn graphic_escape_marks_the_following_byte() {
        let mut s = Screen::primary(Model::Model2);
        let mut rec = vec![Command::EraseWrite.as_byte(), 0xC3];
        rec.extend(sba(0));
        // 0x11 would otherwise be an SBA order; GE forces it to be data.
        rec.extend([Order::Ge.as_byte(), 0x11]);
        apply(&mut s, &rec).unwrap();
        assert_eq!(s.cell(0).byte, 0x11);
        assert!(s.cell(0).graphic_escape);
    }

    #[test]
    fn a_truncated_order_is_reported_not_panicked() {
        let mut s = Screen::primary(Model::Model2);
        for tail in [
            vec![Order::Sba.as_byte(), 0x40],
            vec![Order::Sf.as_byte()],
            vec![Order::Ra.as_byte(), 0x40, 0x40],
            vec![Order::Sfe.as_byte(), 2, 0xC0],
        ] {
            let mut rec = vec![Command::Write.as_byte(), 0xC3];
            rec.extend(tail);
            assert!(matches!(apply(&mut s, &rec), Err(ParseError::Truncated(_))));
        }
    }

    #[test]
    fn bad_commands_and_empty_records_are_errors() {
        let mut s = Screen::primary(Model::Model2);
        assert_eq!(apply(&mut s, &[]), Err(ParseError::Empty));
        assert_eq!(
            apply(&mut s, &[0x99]),
            Err(ParseError::UnknownCommand(0x99))
        );
    }

    #[test]
    fn write_structured_field_returns_its_fields() {
        let mut s = Screen::primary(Model::Model2);
        // Read Partition (Query): length 5, SFID 0x01, PID 0xFF, type 0x02.
        let rec = [
            Command::WriteStructuredField.as_byte(),
            0x00,
            0x05,
            0x01,
            0xFF,
            0x02,
        ];
        let parsed = apply(&mut s, &rec).unwrap();
        assert_eq!(parsed.structured_fields, vec![vec![0x01, 0xFF, 0x02]]);
    }

    #[test]
    fn structured_fields_split_on_their_length_prefix() {
        let data = [0x00, 0x05, 0x01, 0xFF, 0x02, 0x00, 0x04, 0x03, 0x80];
        assert_eq!(
            split_structured_fields(&data),
            vec![vec![0x01, 0xFF, 0x02], vec![0x03, 0x80]]
        );
        // A zero length means "everything that is left".
        assert_eq!(
            split_structured_fields(&[0x00, 0x00, 0xAA, 0xBB]),
            vec![vec![0xAA, 0xBB]]
        );
    }
}
