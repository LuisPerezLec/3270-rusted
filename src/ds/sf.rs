//! Structured fields, including the Query Reply a host asks for with
//! Read Partition.
//!
//! Many hosts send Read Partition (Query) straight after negotiation and wait
//! for the answer before painting anything, so a client that ignores it simply
//! hangs. Field layouts below were checked byte for byte against what s3270
//! sends.

use crate::screen::Model;

/// Structured field id: Read Partition, from the host.
pub const READ_PARTITION: u8 = 0x01;
/// Structured field id: Query Reply, from the terminal.
pub const QUERY_REPLY: u8 = 0x81;
/// Read Partition type: Query.
pub const RP_QUERY: u8 = 0x02;
/// Read Partition type: Query List.
pub const RP_QUERY_LIST: u8 = 0x03;

/// Query Reply codes this client reports.
pub const QR_SUMMARY: u8 = 0x80;
pub const QR_USABLE_AREA: u8 = 0x81;
pub const QR_CHARACTER_SETS: u8 = 0x85;
pub const QR_COLOR: u8 = 0x86;
pub const QR_HIGHLIGHTING: u8 = 0x87;
pub const QR_REPLY_MODES: u8 = 0x88;
pub const QR_IMPLICIT_PARTITION: u8 = 0xA6;

/// The name of a Query Reply code, for tracing.
pub fn query_code_name(code: u8) -> &'static str {
    match code {
        0x80 => "Summary",
        0x81 => "UsableArea",
        0x84 => "AlphanumericPartitions",
        0x85 => "CharacterSets",
        0x86 => "Color",
        0x87 => "Highlighting",
        0x88 => "ReplyModes",
        0x95 => "DistributedDataManagement",
        0xA1 => "RPQNames",
        0xA6 => "ImplicitPartition",
        0xFF => "Null",
        _ => "unknown",
    }
}

/// True when this structured field is a Read Partition asking for a Query Reply.
pub fn is_read_partition_query(sf: &[u8]) -> bool {
    sf.len() >= 3 && sf[0] == READ_PARTITION && matches!(sf[2], RP_QUERY | RP_QUERY_LIST)
}

/// Wrap a Query Reply body in its length prefix and structured field id.
fn wrap(code: u8, body: &[u8], out: &mut Vec<u8>) {
    // The length counts itself, the id and the code.
    let len = (body.len() + 4) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.push(QUERY_REPLY);
    out.push(code);
    out.extend_from_slice(body);
}

/// Build the inbound Query Reply record: AID `0x88` then structured fields.
///
/// Reports only what this crate actually implements. Advertising a capability
/// that is not rendered makes the host send data the client cannot draw, which
/// is worse than not claiming it.
pub fn build_query_reply(model: Model, color: bool) -> Vec<u8> {
    let (alt_rows, alt_cols) = model.alternate();
    let (pri_rows, pri_cols) = Model::PRIMARY;

    let mut out = vec![super::Aid::StructuredField.as_byte().expect("encodes")];

    // Summary: the codes that follow.
    let mut codes = vec![
        QR_SUMMARY,
        QR_USABLE_AREA,
        QR_HIGHLIGHTING,
        QR_REPLY_MODES,
        QR_IMPLICIT_PARTITION,
    ];
    if color {
        codes.push(QR_COLOR);
    }
    codes.sort_unstable();
    wrap(QR_SUMMARY, &codes, &mut out);

    // Usable Area: flags, width, height, units, then the physical dimensions.
    let mut ua = vec![0x01, 0x00];
    ua.extend_from_slice(&alt_cols.to_be_bytes());
    ua.extend_from_slice(&alt_rows.to_be_bytes());
    ua.push(0x01); // units: inches
    ua.extend_from_slice(&0x000A_02E5u32.to_be_bytes()); // Xr
    ua.extend_from_slice(&0x0002_006Fu32.to_be_bytes()); // Yr
    ua.extend_from_slice(&[0x09, 0x0C]); // AW, AH
    ua.extend_from_slice(&(alt_rows * alt_cols).to_be_bytes());
    wrap(QR_USABLE_AREA, &ua, &mut out);

    if color {
        // Colour: flags, pair count, then (attribute, colour) pairs.
        let palette = [0xF1u8, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7];
        let mut c = vec![0x00, (palette.len() + 1) as u8];
        c.extend_from_slice(&[0x00, 0xF4]); // default maps to green
        for p in palette {
            c.extend_from_slice(&[p, p]);
        }
        wrap(QR_COLOR, &c, &mut out);
    }

    // Highlighting: pair count, then (value, action) pairs.
    let highlights = [0x00u8, 0xF1, 0xF2, 0xF4, 0xF8];
    let mut h = vec![highlights.len() as u8];
    for v in highlights {
        h.extend_from_slice(&[v, if v == 0x00 { 0xF0 } else { v }]);
    }
    wrap(QR_HIGHLIGHTING, &h, &mut out);

    // Reply Modes: field, extended field, character.
    wrap(QR_REPLY_MODES, &[0x00, 0x01, 0x02], &mut out);

    // Implicit Partition: a self-defining parameter with both screen sizes.
    let mut ip = vec![0x00, 0x00, 0x0B, 0x01, 0x00];
    ip.extend_from_slice(&pri_cols.to_be_bytes());
    ip.extend_from_slice(&pri_rows.to_be_bytes());
    ip.extend_from_slice(&alt_cols.to_be_bytes());
    ip.extend_from_slice(&alt_rows.to_be_bytes());
    wrap(QR_IMPLICIT_PARTITION, &ip, &mut out);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ds::{inbound, parse::split_structured_fields, Aid};

    #[test]
    fn a_read_partition_query_is_recognised() {
        assert!(is_read_partition_query(&[0x01, 0xFF, 0x02]));
        assert!(is_read_partition_query(&[0x01, 0xFF, 0x03]));
        assert!(!is_read_partition_query(&[0x01, 0xFF, 0x09]));
        assert!(!is_read_partition_query(&[0x03, 0x00]));
        assert!(!is_read_partition_query(&[]));
    }

    #[test]
    fn the_query_reply_parses_back_as_structured_fields() {
        let record = build_query_reply(Model::Model5, true);
        let parsed = inbound::parse(&record).expect("parses");
        assert_eq!(parsed.aid, Aid::StructuredField);

        let codes: Vec<u8> = parsed
            .structured
            .iter()
            .filter(|sf| sf.first() == Some(&QUERY_REPLY))
            .map(|sf| sf[1])
            .collect();
        assert!(codes.contains(&QR_SUMMARY));
        assert!(codes.contains(&QR_USABLE_AREA));
        assert!(codes.contains(&QR_IMPLICIT_PARTITION));
        assert!(codes.contains(&QR_COLOR));
    }

    #[test]
    fn usable_area_reports_the_alternate_geometry() {
        let record = build_query_reply(Model::Model5, true);
        let sfs = split_structured_fields(&record[1..]);
        let ua = sfs
            .iter()
            .find(|sf| sf.len() > 2 && sf[1] == QR_USABLE_AREA)
            .expect("usable area present");
        let body = &ua[2..];
        let cols = u16::from_be_bytes([body[2], body[3]]);
        let rows = u16::from_be_bytes([body[4], body[5]]);
        assert_eq!((cols, rows), (132, 27), "model 5 is 27 rows of 132");
        let buffer = u16::from_be_bytes([body[17], body[18]]);
        assert_eq!(buffer, 27 * 132);
    }

    #[test]
    fn implicit_partition_reports_both_screen_sizes() {
        let record = build_query_reply(Model::Model4, true);
        let sfs = split_structured_fields(&record[1..]);
        let ip = sfs
            .iter()
            .find(|sf| sf.len() > 2 && sf[1] == QR_IMPLICIT_PARTITION)
            .expect("implicit partition present");
        let b = &ip[2..];
        assert_eq!(b[3], 0x01, "self-defining parameter type");
        assert_eq!(u16::from_be_bytes([b[5], b[6]]), 80, "default cols");
        assert_eq!(u16::from_be_bytes([b[7], b[8]]), 24, "default rows");
        assert_eq!(u16::from_be_bytes([b[9], b[10]]), 80, "alternate cols");
        assert_eq!(u16::from_be_bytes([b[11], b[12]]), 43, "alternate rows");
    }

    #[test]
    fn a_monochrome_terminal_does_not_claim_colour() {
        let record = build_query_reply(Model::Model2, false);
        let sfs = split_structured_fields(&record[1..]);
        assert!(
            !sfs.iter().any(|sf| sf.len() > 2 && sf[1] == QR_COLOR),
            "must not advertise what it cannot render"
        );
    }

    #[test]
    fn every_structured_field_length_is_self_consistent() {
        for model in [Model::Model2, Model::Model3, Model::Model4, Model::Model5] {
            let record = build_query_reply(model, true);
            // Walking by the length prefixes must consume the record exactly.
            let mut i = 1;
            while i < record.len() {
                let len = usize::from(u16::from_be_bytes([record[i], record[i + 1]]));
                assert!(len >= 4, "length must cover itself, the id and the code");
                i += len;
            }
            assert_eq!(i, record.len(), "{model} record has a trailing remainder");
        }
    }
}
