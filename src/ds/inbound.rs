//! Building and parsing terminal-to-host records.
//!
//! The encoding rules here are the ones clients most often get wrong, and all
//! three are verified against x3270's `ctlr_read_modified`:
//!
//! * `CLEAR` and `PA1`-`PA3` send the AID byte **alone** — no cursor, no fields.
//! * `SYSREQ` sends `SOH % / STX`, which is not an AID record at all.
//! * Null positions inside a modified field are **omitted**, not sent as
//!   spaces, so `AB` followed by nulls goes out as two bytes.

use super::addr;
use super::{Aid, Order, SYSREQ_RECORD};
use crate::screen::Screen;

/// One field in a terminal-to-host record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundField {
    /// Address of the field's first data position.
    pub addr: u16,
    /// The bytes the terminal sent, nulls already omitted.
    pub data: Vec<u8>,
}

/// A decoded terminal-to-host record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRecord {
    pub aid: Aid,
    /// `None` for a short read, which carries no cursor.
    pub cursor: Option<u16>,
    pub fields: Vec<InboundField>,
    /// Structured fields, when the AID is `0x88`.
    pub structured: Vec<Vec<u8>>,
}

/// Encode a Read Modified reply for `aid`.
///
/// `all` selects Read Modified All semantics, which suppresses the short-read
/// shortcut so even `CLEAR` reports its fields.
pub fn read_modified(screen: &Screen, aid: Aid, all: bool) -> Vec<u8> {
    if aid == Aid::SysReq {
        return SYSREQ_RECORD.to_vec();
    }

    let aid_byte = match aid.as_byte() {
        Some(b) => b,
        // An out-of-range PF/PA number cannot be encoded; treat it as no AID
        // rather than sending a wrong key.
        None => return Vec::new(),
    };

    let mut out = vec![aid_byte];

    if aid.is_short_read() && !all {
        return out;
    }

    out.extend_from_slice(&addr::encode(screen.cursor()));

    if !aid.sends_field_data() && !all {
        return out;
    }

    if !screen.is_formatted() {
        // An unformatted screen has no fields: send every non-null byte.
        for a in 0..screen.size() {
            let byte = screen.cell(a).byte;
            if byte != 0x00 {
                out.push(byte);
            }
        }
        return out;
    }

    for field in screen.fields() {
        if !field.attr.is_modified() {
            continue;
        }
        out.push(Order::Sba.as_byte());
        out.extend_from_slice(&addr::encode(field.start));
        for i in 0..field.len {
            let cell = screen.cell(field.start.wrapping_add(i));
            if cell.byte == 0x00 {
                // Nulls are omitted entirely, not sent as spaces.
                continue;
            }
            if cell.graphic_escape {
                out.push(Order::Ge.as_byte());
            }
            out.push(cell.byte);
        }
    }
    out
}

/// Encode a Read Buffer reply: the whole buffer, attributes included.
pub fn read_buffer(screen: &Screen) -> Vec<u8> {
    let mut out = vec![Aid::None.as_byte().expect("NoAID encodes")];
    out.extend_from_slice(&addr::encode(screen.cursor()));
    for a in 0..screen.size() {
        let cell = screen.cell(a);
        match cell.field {
            Some(attr) => {
                out.push(Order::Sf.as_byte());
                out.push(attr.as_byte());
            }
            None => {
                if cell.graphic_escape {
                    out.push(Order::Ge.as_byte());
                }
                out.push(cell.byte);
            }
        }
    }
    out
}

/// Parse a terminal-to-host record.
///
/// Useful for tests, and for anyone implementing the host side. The TN3270E
/// header, if any, must already be stripped.
pub fn parse(data: &[u8]) -> Option<InboundRecord> {
    let &aid_byte = data.first()?;
    let aid = Aid::from_byte(aid_byte);

    if aid == Aid::StructuredField {
        return Some(InboundRecord {
            aid,
            cursor: None,
            fields: Vec::new(),
            structured: super::parse::split_structured_fields(&data[1..]),
        });
    }

    // A short read is the AID byte alone.
    if data.len() < 3 {
        return Some(InboundRecord {
            aid,
            cursor: None,
            fields: Vec::new(),
            structured: Vec::new(),
        });
    }

    let cursor = addr::decode(data[1], data[2]);
    let mut fields: Vec<InboundField> = Vec::new();
    let mut i = 3;
    while i < data.len() {
        if data[i] == Order::Sba.as_byte() && i + 2 < data.len() {
            fields.push(InboundField {
                addr: addr::decode(data[i + 1], data[i + 2]),
                data: Vec::new(),
            });
            i += 3;
        } else if data[i] == Order::Ge.as_byte() && i + 1 < data.len() {
            if let Some(f) = fields.last_mut() {
                f.data.push(data[i + 1]);
            }
            i += 2;
        } else {
            if let Some(f) = fields.last_mut() {
                f.data.push(data[i]);
            }
            i += 1;
        }
    }

    Some(InboundRecord {
        aid,
        cursor: Some(cursor),
        fields,
        structured: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ds::attr::{FieldAttr, Intensity};
    use crate::screen::{Model, Screen};

    /// Two unprotected fields; the first is modified and holds "AB".
    fn formatted() -> Screen {
        let mut s = Screen::primary(Model::Model2);
        s.cell_mut(0).field = Some(FieldAttr::new(false, false, Intensity::Normal, true));
        s.cell_mut(1).byte = 0xC1; // A
        s.cell_mut(2).byte = 0xC2; // B
                                   // positions 3..9 stay null
        s.cell_mut(10).field = Some(FieldAttr::new(false, false, Intensity::Normal, false));
        s.cell_mut(11).byte = 0xC3; // C, but unmodified
        s.set_cursor(s.addr_of(1, 4));
        s
    }

    #[test]
    fn enter_sends_aid_cursor_and_modified_fields_only() {
        let s = formatted();
        let rec = read_modified(&s, Aid::Enter, false);
        let [chi, clo] = addr::encode(s.cursor());
        let [fhi, flo] = addr::encode(1);
        assert_eq!(
            rec,
            vec![0x7D, chi, clo, Order::Sba.as_byte(), fhi, flo, 0xC1, 0xC2],
            "unmodified field must not be sent, and trailing nulls are omitted"
        );
    }

    #[test]
    fn nulls_inside_a_field_are_omitted_not_spaced() {
        let mut s = formatted();
        s.cell_mut(3).byte = 0x00; // a hole
        s.cell_mut(4).byte = 0xC4; // D after the hole
        let rec = read_modified(&s, Aid::Enter, false);
        // Data bytes come out contiguous: A B D.
        assert_eq!(&rec[rec.len() - 3..], &[0xC1, 0xC2, 0xC4]);
    }

    #[test]
    fn clear_and_the_pa_keys_send_the_aid_alone() {
        let s = formatted();
        assert_eq!(read_modified(&s, Aid::Clear, false), vec![0x6D]);
        assert_eq!(read_modified(&s, Aid::Pa(1), false), vec![0x6C]);
        assert_eq!(read_modified(&s, Aid::Pa(3), false), vec![0x6B]);
    }

    #[test]
    fn read_modified_all_overrides_the_short_read() {
        let s = formatted();
        let rec = read_modified(&s, Aid::Clear, true);
        assert!(
            rec.len() > 1,
            "Read Modified All reports fields even for CLEAR"
        );
        assert_eq!(rec[0], 0x6D);
    }

    #[test]
    fn select_sends_a_cursor_but_no_field_data() {
        let s = formatted();
        let rec = read_modified(&s, Aid::Select, false);
        assert_eq!(rec.len(), 3, "AID plus cursor, nothing else");
        assert_eq!(rec[0], 0x7E);
    }

    #[test]
    fn sysreq_is_not_an_aid_record() {
        let s = formatted();
        assert_eq!(
            read_modified(&s, Aid::SysReq, false),
            SYSREQ_RECORD.to_vec()
        );
    }

    #[test]
    fn an_unformatted_screen_sends_its_whole_contents() {
        let mut s = Screen::primary(Model::Model2);
        s.cell_mut(0).byte = 0xC1;
        s.cell_mut(5).byte = 0xC2;
        let rec = read_modified(&s, Aid::Enter, false);
        assert_eq!(&rec[3..], &[0xC1, 0xC2], "nulls between them are dropped");
    }

    #[test]
    fn a_field_with_nothing_typed_sends_only_its_address() {
        let mut s = Screen::primary(Model::Model2);
        // Modified, but every position null: the host still learns it changed.
        s.cell_mut(0).field = Some(FieldAttr::new(false, false, Intensity::Normal, true));
        let rec = read_modified(&s, Aid::Enter, false);
        let [hi, lo] = addr::encode(1);
        assert_eq!(rec, vec![0x7D, 0x40, 0x40, Order::Sba.as_byte(), hi, lo]);
    }

    #[test]
    fn encoding_round_trips_through_the_parser() {
        let s = formatted();
        let wire = read_modified(&s, Aid::Pf(3), false);
        let rec = parse(&wire).expect("parses");
        assert_eq!(rec.aid, Aid::Pf(3));
        assert_eq!(rec.cursor, Some(s.cursor()));
        assert_eq!(rec.fields.len(), 1);
        assert_eq!(rec.fields[0].addr, 1);
        assert_eq!(rec.fields[0].data, vec![0xC1, 0xC2]);
    }

    #[test]
    fn a_short_read_parses_with_no_cursor() {
        let rec = parse(&[0x6D]).expect("parses");
        assert_eq!(rec.aid, Aid::Clear);
        assert_eq!(rec.cursor, None);
        assert!(rec.fields.is_empty());
    }

    #[test]
    fn an_inbound_structured_field_parses_as_such() {
        // AID 0x88 then a Query Reply carrying Usable Area.
        let mut wire = vec![0x88];
        let body = [0x81u8, 0x81, 0x00, 0x00, 0x00, 0x50, 0x00, 0x18];
        wire.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        wire.extend_from_slice(&body);
        let rec = parse(&wire).expect("parses");
        assert_eq!(rec.aid, Aid::StructuredField);
        assert_eq!(rec.structured, vec![body.to_vec()]);
    }

    #[test]
    fn read_buffer_includes_attributes() {
        let s = formatted();
        let rec = read_buffer(&s);
        assert_eq!(rec[0], 0x60, "Read Buffer replies with no AID");
        // The field attribute at address 0 appears as SF + attribute byte.
        assert_eq!(rec[3], Order::Sf.as_byte());
        assert_eq!(rec[5], 0xC1, "then the data byte at address 1");
    }

    #[test]
    fn graphic_escape_survives_a_round_trip() {
        let mut s = Screen::primary(Model::Model2);
        s.cell_mut(0).field = Some(FieldAttr::new(false, false, Intensity::Normal, true));
        s.cell_mut(1).byte = 0x11;
        s.cell_mut(1).graphic_escape = true;
        let wire = read_modified(&s, Aid::Enter, false);
        let rec = parse(&wire).expect("parses");
        assert_eq!(
            rec.fields[0].data,
            vec![0x11],
            "GE prefix consumed, byte kept"
        );
    }
}
