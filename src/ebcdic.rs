//! EBCDIC code page conversion.
//!
//! The 3270 data stream carries text in EBCDIC.  Tables here are generated
//! from the reference mappings, so a byte round-trips exactly.
//!
//! Every mapping is a single byte to a single Unicode scalar; some code pages
//! leave a few bytes undefined, which is why decoding yields an `Option`.

/// Sentinel for a byte that this code page does not define.
const UNDEF: u16 = 0xFFFF;

/// A single-byte (SBCS) EBCDIC code page.
#[derive(Clone, Copy)]
pub struct CodePage {
    name: &'static str,
    description: &'static str,
    decode: &'static [u16; 256],
    /// Sorted by code point, for binary search on the encode path.
    encode: &'static [(u16, u8)],
}

impl CodePage {
    /// The canonical name, for example `"cp037"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Where this code page is typically deployed.
    pub const fn description(&self) -> &'static str {
        self.description
    }

    /// Decode one EBCDIC byte, or `None` if this code page leaves it undefined.
    pub fn decode_byte(self, byte: u8) -> Option<char> {
        let cp = self.decode[byte as usize];
        if cp == UNDEF {
            None
        } else {
            char::from_u32(cp as u32)
        }
    }

    /// Encode one character, or `None` if it has no representation here.
    pub fn encode_char(self, ch: char) -> Option<u8> {
        let cp = u16::try_from(u32::from(ch)).ok()?;
        self.encode
            .binary_search_by_key(&cp, |&(c, _)| c)
            .ok()
            .map(|i| self.encode[i].1)
    }

    /// Decode a buffer, substituting `replacement` for undefined bytes.
    pub fn decode_lossy(self, bytes: &[u8], replacement: char) -> String {
        bytes
            .iter()
            .map(|&b| self.decode_byte(b).unwrap_or(replacement))
            .collect()
    }

    /// Encode a string, substituting `replacement` for characters this code
    /// page cannot represent.  `replacement` is an EBCDIC byte.
    pub fn encode_lossy(self, text: &str, replacement: u8) -> Vec<u8> {
        text.chars()
            .map(|c| self.encode_char(c).unwrap_or(replacement))
            .collect()
    }

    /// Look up a code page by name or common alias, case-insensitively.
    /// Accepts `"cp037"`, `"CP037"`, `"037"`, `"37"`, `"ibm-1140"` and the
    /// aliases s3270 uses, such as `"us"` and `"german"`.
    pub fn lookup(name: &str) -> Option<CodePage> {
        let lower = name.trim().to_ascii_lowercase();
        let bare = lower
            .strip_prefix("ibm-")
            .or_else(|| lower.strip_prefix("ibm"))
            .unwrap_or(&lower);
        let canonical: String = match bare {
            "us" | "us-intl" => "cp037".into(),
            "german" => "cp273".into(),
            "international" => "cp500".into(),
            "turkish" => "cp1026".into(),
            "us-euro" => "cp1140".into(),
            other => {
                let digits = other.strip_prefix("cp").unwrap_or(other);
                if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                    // Pad to the conventional three digits: 37 -> cp037.
                    match digits.parse::<u32>() {
                        Ok(n) if n < 1000 => format!("cp{n:03}"),
                        Ok(n) => format!("cp{n}"),
                        Err(_) => return None,
                    }
                } else {
                    other.into()
                }
            }
        };
        tables::ALL.iter().copied().find(|p| p.name == canonical)
    }

    /// Every code page compiled in.
    pub fn all() -> &'static [CodePage] {
        tables::ALL
    }
}

impl core::fmt::Debug for CodePage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name)
    }
}

impl PartialEq for CodePage {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for CodePage {}

/// EBCDIC `?`, the conventional stand-in for an unmappable character.
pub const SUB: u8 = 0x6F;

mod tables;

pub use tables::{CP037, CP1026, CP1140, CP273, CP500, DEFAULT};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_defined_byte_round_trips_in_every_code_page() {
        for page in CodePage::all() {
            for byte in 0u8..=255 {
                if let Some(ch) = page.decode_byte(byte) {
                    assert_eq!(
                        page.encode_char(ch),
                        Some(byte),
                        "{}: byte 0x{byte:02X} decoded to {ch:?} but did not encode back",
                        page.name()
                    );
                }
            }
        }
    }

    #[test]
    fn cp037_matches_known_values() {
        // Checked against the reference mapping: these are the bytes a host
        // actually puts on the wire.
        assert_eq!(
            CP037.encode_lossy("LOGON", SUB),
            vec![0xD3, 0xD6, 0xC7, 0xD6, 0xD5]
        );
        assert_eq!(
            CP037.decode_lossy(&[0xC8, 0x85, 0x93, 0x93, 0x96], '?'),
            "Hello"
        );
        assert_eq!(CP037.encode_char(' '), Some(0x40));
        assert_eq!(CP037.encode_char('0'), Some(0xF0));
        assert_eq!(CP037.encode_char('?'), Some(SUB));
        assert_eq!(CP037.decode_byte(0x00), Some('\0'));
    }

    #[test]
    fn cp1140_is_cp037_plus_the_euro_sign() {
        assert_eq!(CP1140.decode_byte(0x9F), Some('\u{20AC}'));
        assert_eq!(CP037.decode_byte(0x9F), Some('\u{00A4}'));
        // Every alphanumeric position is identical between the two.
        for byte in 0u8..=255 {
            let a = CP037.decode_byte(byte).unwrap_or('\0');
            if a.is_ascii_alphanumeric() {
                assert_eq!(CP1140.decode_byte(byte), Some(a));
            }
        }
    }

    #[test]
    fn code_pages_beyond_latin1_are_representable() {
        // cp273 maps 0xBC to OVERLINE, which is why the tables are u16 and
        // not u8: this code page reaches outside Latin-1.
        assert_eq!(CP273.decode_byte(0xBC), Some('\u{203E}'));
        assert_eq!(CP273.encode_char('\u{203E}'), Some(0xBC));
    }

    #[test]
    fn lookup_accepts_names_and_aliases() {
        assert_eq!(CodePage::lookup("cp037"), Some(CP037));
        assert_eq!(CodePage::lookup("CP037"), Some(CP037));
        assert_eq!(CodePage::lookup("us"), Some(CP037));
        assert_eq!(CodePage::lookup("cp37"), Some(CP037));
        assert_eq!(CodePage::lookup("ibm-1140"), Some(CP1140));
        assert_eq!(CodePage::lookup("1140"), Some(CP1140));
        assert_eq!(CodePage::lookup("037"), Some(CP037));
        assert_eq!(CodePage::lookup("37"), Some(CP037));
        assert_eq!(CodePage::lookup("ibm037"), Some(CP037));
        assert_eq!(CodePage::lookup("9999"), None);
        assert_eq!(CodePage::lookup("german"), Some(CP273));
        assert_eq!(CodePage::lookup("nonsense"), None);
    }

    #[test]
    fn unmappable_characters_become_the_substitute() {
        assert_eq!(CP037.encode_char('\u{1F600}'), None);
        assert_eq!(
            CP037.encode_lossy("a\u{1F600}b", SUB),
            vec![0x81, SUB, 0x82]
        );
    }
}
