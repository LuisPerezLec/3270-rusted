//! Buffer addressing.
//!
//! A 3270 buffer address is two bytes, in one of two encodings. Which one is
//! in use is inferred from the top two bits of the first byte, and getting
//! this wrong is a classic source of screens that render one cell off.
//!
//! * **12-bit**, the form every real host emits for buffers up to 4096 cells:
//!   six bits per byte, each mapped through a table so both bytes land on
//!   printable EBCDIC graphics.
//! * **14-bit**, plain binary, used for larger buffers. Recognised by the top
//!   two bits of the first byte being `00`.
//!
//! Models 2 to 5 top out at 3564 cells, so 12-bit covers all of them.

/// Maps a 6-bit value to a printable EBCDIC graphic, for 12-bit addresses.
const CODES: [u8; 64] = [
    0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
];

/// The largest address expressible in the 12-bit graphic form.
pub const MAX_12BIT: u16 = 0x0FFF;
/// The largest address expressible in the 14-bit binary form.
pub const MAX_14BIT: u16 = 0x3FFF;

/// Encode a buffer address, choosing 12-bit when it fits.
///
/// Addresses above [`MAX_14BIT`] are truncated to 14 bits; callers that can
/// exceed that should reject the address themselves.
pub fn encode(addr: u16) -> [u8; 2] {
    if addr <= MAX_12BIT {
        [
            CODES[(addr >> 6) as usize & 0x3F],
            CODES[addr as usize & 0x3F],
        ]
    } else {
        [((addr >> 8) as u8) & 0x3F, addr as u8]
    }
}

/// Decode a buffer address in either encoding.
pub fn decode(hi: u8, lo: u8) -> u16 {
    if hi & 0xC0 == 0x00 {
        // 14-bit binary.
        (u16::from(hi & 0x3F) << 8) | u16::from(lo)
    } else {
        // 12-bit: six significant bits from each byte.
        (u16::from(hi & 0x3F) << 6) | u16::from(lo & 0x3F)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twelve_bit_round_trips_across_every_model_geometry() {
        for (rows, cols) in [(24u16, 80u16), (32, 80), (43, 80), (27, 132)] {
            for addr in 0..rows * cols {
                let [hi, lo] = encode(addr);
                assert_eq!(decode(hi, lo), addr, "{rows}x{cols} addr {addr}");
            }
        }
    }

    #[test]
    fn twelve_bit_uses_printable_graphics() {
        // The whole point of the code table: neither byte may collide with an
        // order code, or a host's own parser would go wrong.
        for addr in 0..=MAX_12BIT {
            let [hi, lo] = encode(addr);
            assert!(CODES.contains(&hi) && CODES.contains(&lo), "addr {addr}");
        }
    }

    #[test]
    fn fourteen_bit_round_trips_above_the_twelve_bit_limit() {
        for addr in [MAX_12BIT + 1, 0x1234, 0x2000, MAX_14BIT] {
            let [hi, lo] = encode(addr);
            assert_eq!(hi & 0xC0, 0x00, "must signal 14-bit form");
            assert_eq!(decode(hi, lo), addr);
        }
    }

    #[test]
    fn known_wire_values_match_the_reference() {
        // Address 0 is the origin; hosts emit 0x40 0x40.
        assert_eq!(encode(0), [0x40, 0x40]);
        // Last cell of a model 2 screen, 24x80 - 1 = 1919.
        assert_eq!(decode(0x5D, 0x7F), 1919);
        assert_eq!(encode(1919), [0x5D, 0x7F]);
    }
}
