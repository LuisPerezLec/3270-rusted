//! Field attributes, basic and extended.

/// The basic 3270 field attribute, as carried by a Start Field order.
///
/// The top two bits are forced on so the byte is a printable EBCDIC graphic;
/// they carry no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldAttr(pub u8);

/// Bit forced on to keep the attribute byte printable.
pub const PRINTABLE: u8 = 0xC0;
pub const PROTECTED: u8 = 0x20;
pub const NUMERIC: u8 = 0x10;
pub const INTENSITY: u8 = 0x0C;
pub const MODIFIED: u8 = 0x01;

/// How a field is displayed and whether a selector pen can detect it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intensity {
    /// Normal, not detectable.
    Normal,
    /// Normal, detectable.
    Detectable,
    /// Intensified, detectable.
    Intensified,
    /// Not displayed: password fields.
    Hidden,
}

impl FieldAttr {
    /// An unprotected, normal-intensity field.
    pub const UNPROTECTED: FieldAttr = FieldAttr(PRINTABLE);

    /// Build an attribute from its parts.
    pub fn new(protected: bool, numeric: bool, intensity: Intensity, modified: bool) -> Self {
        let mut bits = PRINTABLE;
        if protected {
            bits |= PROTECTED;
        }
        if numeric {
            bits |= NUMERIC;
        }
        bits |= match intensity {
            Intensity::Normal => 0x00,
            Intensity::Detectable => 0x04,
            Intensity::Intensified => 0x08,
            Intensity::Hidden => 0x0C,
        };
        if modified {
            bits |= MODIFIED;
        }
        FieldAttr(bits)
    }

    /// The wire byte.
    pub const fn as_byte(self) -> u8 {
        self.0 | PRINTABLE
    }

    /// True when the operator cannot type into this field.
    pub const fn is_protected(self) -> bool {
        self.0 & PROTECTED != 0
    }

    /// True when the field accepts digits and a few signs only.
    pub const fn is_numeric(self) -> bool {
        self.0 & NUMERIC != 0
    }

    /// True when the field has been typed into since the last reset.
    ///
    /// The host reads only modified fields, so this bit decides what comes
    /// back. A host can also preset it, which makes a field return even
    /// though the operator never touched it.
    pub const fn is_modified(self) -> bool {
        self.0 & MODIFIED != 0
    }

    /// Set or clear the modified-data-tag.
    pub fn set_modified(&mut self, modified: bool) {
        if modified {
            self.0 |= MODIFIED;
        } else {
            self.0 &= !MODIFIED;
        }
    }

    /// Display intensity and detectability.
    pub const fn intensity(self) -> Intensity {
        match self.0 & INTENSITY {
            0x00 => Intensity::Normal,
            0x04 => Intensity::Detectable,
            0x08 => Intensity::Intensified,
            _ => Intensity::Hidden,
        }
    }

    /// True when the field is not displayed at all.
    pub const fn is_hidden(self) -> bool {
        matches!(self.intensity(), Intensity::Hidden)
    }

    /// True when the operator may type into this field.
    pub const fn is_input(self) -> bool {
        !self.is_protected()
    }

    /// True when the field is protected *and* numeric, which by convention
    /// marks it as auto-skip: the cursor jumps over it while tabbing.
    pub const fn is_autoskip(self) -> bool {
        self.is_protected() && self.is_numeric()
    }
}

impl From<u8> for FieldAttr {
    fn from(byte: u8) -> Self {
        FieldAttr(byte)
    }
}

/// Type codes for extended attributes, used by Start Field Extended, Set
/// Attribute and Modify Field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtType {
    /// Reset every extended attribute.
    All,
    /// The basic field attribute, carried inside an SFE.
    Basic,
    Validation,
    Outlining,
    Highlighting,
    Foreground,
    CharacterSet,
    Background,
    Transparency,
    Unknown(u8),
}

impl ExtType {
    pub const fn from_byte(byte: u8) -> ExtType {
        match byte {
            0x00 => ExtType::All,
            0xC0 => ExtType::Basic,
            0xC1 => ExtType::Validation,
            0xC2 => ExtType::Outlining,
            0x41 => ExtType::Highlighting,
            0x42 => ExtType::Foreground,
            0x43 => ExtType::CharacterSet,
            0x45 => ExtType::Background,
            0x46 => ExtType::Transparency,
            other => ExtType::Unknown(other),
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            ExtType::All => 0x00,
            ExtType::Basic => 0xC0,
            ExtType::Validation => 0xC1,
            ExtType::Outlining => 0xC2,
            ExtType::Highlighting => 0x41,
            ExtType::Foreground => 0x42,
            ExtType::CharacterSet => 0x43,
            ExtType::Background => 0x45,
            ExtType::Transparency => 0x46,
            ExtType::Unknown(b) => b,
        }
    }
}

/// The 3270 colour palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    /// The terminal's default for this field.
    #[default]
    Default,
    Blue,
    Red,
    Pink,
    Green,
    Turquoise,
    Yellow,
    White,
    Black,
    DeepBlue,
    Orange,
    Purple,
    PaleGreen,
    PaleTurquoise,
    Grey,
    Other(u8),
}

impl Color {
    pub const fn from_byte(byte: u8) -> Color {
        match byte {
            0x00 => Color::Default,
            0xF1 => Color::Blue,
            0xF2 => Color::Red,
            0xF3 => Color::Pink,
            0xF4 => Color::Green,
            0xF5 => Color::Turquoise,
            0xF6 => Color::Yellow,
            0xF0 | 0xF7 => Color::White,
            0xF8 => Color::Black,
            0xF9 => Color::DeepBlue,
            0xFA => Color::Orange,
            0xFB => Color::Purple,
            0xFC => Color::PaleGreen,
            0xFD => Color::PaleTurquoise,
            0xFE => Color::Grey,
            other => Color::Other(other),
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            Color::Default => 0x00,
            Color::Blue => 0xF1,
            Color::Red => 0xF2,
            Color::Pink => 0xF3,
            Color::Green => 0xF4,
            Color::Turquoise => 0xF5,
            Color::Yellow => 0xF6,
            Color::White => 0xF7,
            Color::Black => 0xF8,
            Color::DeepBlue => 0xF9,
            Color::Orange => 0xFA,
            Color::Purple => 0xFB,
            Color::PaleGreen => 0xFC,
            Color::PaleTurquoise => 0xFD,
            Color::Grey => 0xFE,
            Color::Other(b) => b,
        }
    }
}

/// Extended highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Highlight {
    #[default]
    Default,
    Normal,
    Blink,
    Reverse,
    Underscore,
    Intensify,
    Other(u8),
}

impl Highlight {
    pub const fn from_byte(byte: u8) -> Highlight {
        match byte {
            0x00 => Highlight::Default,
            0xF0 => Highlight::Normal,
            0xF1 => Highlight::Blink,
            0xF2 => Highlight::Reverse,
            0xF4 => Highlight::Underscore,
            0xF8 => Highlight::Intensify,
            other => Highlight::Other(other),
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            Highlight::Default => 0x00,
            Highlight::Normal => 0xF0,
            Highlight::Blink => 0xF1,
            Highlight::Reverse => 0xF2,
            Highlight::Underscore => 0xF4,
            Highlight::Intensify => 0xF8,
            Highlight::Other(b) => b,
        }
    }
}

/// The extended attributes that apply to a field or a single cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Extended {
    pub foreground: Color,
    pub background: Color,
    pub highlight: Highlight,
    pub character_set: u8,
}

impl Extended {
    /// True when nothing is set, so the cell renders with terminal defaults.
    pub fn is_default(&self) -> bool {
        *self == Extended::default()
    }

    /// Apply one extended attribute pair, as an SFE or SA order carries it.
    pub fn apply(&mut self, kind: ExtType, value: u8) {
        match kind {
            ExtType::All => *self = Extended::default(),
            ExtType::Foreground => self.foreground = Color::from_byte(value),
            ExtType::Background => self.background = Color::from_byte(value),
            ExtType::Highlighting => self.highlight = Highlight::from_byte(value),
            ExtType::CharacterSet => self.character_set = value,
            // Basic is handled by the caller; the rest do not affect rendering
            // in a headless emulator.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_bits_decode_as_the_reference_does() {
        // 0xE0: protected, normal intensity. A label.
        let a = FieldAttr(0xE0);
        assert!(a.is_protected() && !a.is_numeric() && !a.is_modified());
        assert_eq!(a.intensity(), Intensity::Normal);

        // 0xC0: unprotected, normal. An input field.
        let b = FieldAttr(0xC0);
        assert!(b.is_input() && !b.is_modified());

        // 0xE8: protected, intensified. A highlighted label.
        assert_eq!(FieldAttr(0xE8).intensity(), Intensity::Intensified);

        // 0xCC: unprotected, non-display. A password field.
        let pw = FieldAttr(0xCC);
        assert!(pw.is_input() && pw.is_hidden());

        // 0xC1: unprotected with the MDT preset, so it returns unmodified.
        assert!(FieldAttr(0xC1).is_modified());
    }

    #[test]
    fn protected_and_numeric_together_means_autoskip() {
        assert!(FieldAttr::new(true, true, Intensity::Normal, false).is_autoskip());
        assert!(!FieldAttr::new(true, false, Intensity::Normal, false).is_autoskip());
        assert!(!FieldAttr::new(false, true, Intensity::Normal, false).is_autoskip());
    }

    #[test]
    fn constructing_an_attribute_round_trips_through_its_byte() {
        for protected in [false, true] {
            for numeric in [false, true] {
                for intensity in [
                    Intensity::Normal,
                    Intensity::Detectable,
                    Intensity::Intensified,
                    Intensity::Hidden,
                ] {
                    for modified in [false, true] {
                        let a = FieldAttr::new(protected, numeric, intensity, modified);
                        let b = FieldAttr::from(a.as_byte());
                        assert_eq!(a.is_protected(), b.is_protected());
                        assert_eq!(a.is_numeric(), b.is_numeric());
                        assert_eq!(a.intensity(), b.intensity());
                        assert_eq!(a.is_modified(), b.is_modified());
                    }
                }
            }
        }
    }

    #[test]
    fn modified_flag_toggles() {
        let mut a = FieldAttr::UNPROTECTED;
        assert!(!a.is_modified());
        a.set_modified(true);
        assert!(a.is_modified());
        a.set_modified(false);
        assert!(!a.is_modified());
    }

    #[test]
    fn colours_and_highlights_round_trip() {
        for byte in [0x00u8, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xFE] {
            assert_eq!(Color::from_byte(byte).as_byte(), byte);
        }
        for byte in [0x00u8, 0xF0, 0xF1, 0xF2, 0xF4, 0xF8] {
            assert_eq!(Highlight::from_byte(byte).as_byte(), byte);
        }
        // 0xF0 and 0xF7 both mean neutral/white inbound; encoding picks 0xF7.
        assert_eq!(Color::from_byte(0xF0), Color::White);
    }

    #[test]
    fn extended_attributes_accumulate_and_reset() {
        let mut e = Extended::default();
        assert!(e.is_default());
        e.apply(ExtType::Foreground, 0xF6);
        e.apply(ExtType::Highlighting, 0xF4);
        assert_eq!(e.foreground, Color::Yellow);
        assert_eq!(e.highlight, Highlight::Underscore);
        assert!(!e.is_default());
        e.apply(ExtType::All, 0x00);
        assert!(e.is_default());
    }
}
