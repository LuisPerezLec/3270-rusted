//! The 3270 data stream: commands, orders, attention identifiers.
//!
//! Byte values and names follow x3270's `3270ds.h`, so this module can be
//! read side by side with the reference implementation.

pub mod addr;
pub mod attr;
pub mod inbound;
pub mod parse;
pub mod sf;

pub use attr::{Color, ExtType, Extended, FieldAttr, Highlight, Intensity};
pub use inbound::{read_buffer, read_modified, InboundField, InboundRecord};
pub use parse::{apply, ParseError, Parsed};

/// A host-to-terminal command, the first byte of an outbound record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Update the screen without erasing it.
    Write,
    /// Erase, then write. Also resets the screen to the **primary** 24x80 size.
    EraseWrite,
    /// Erase, then write. Switches the screen to the **alternate** (model) size.
    EraseWriteAlternate,
    /// Send the whole buffer back, attributes included.
    ReadBuffer,
    /// Send back modified fields only.
    ReadModified,
    /// Send back modified fields, ignoring the short-read AIDs.
    ReadModifiedAll,
    /// Clear every unprotected field.
    EraseAllUnprotected,
    /// Carries structured fields, such as Read Partition.
    WriteStructuredField,
}

impl Command {
    pub const fn from_byte(byte: u8) -> Option<Command> {
        match byte {
            0xF1 => Some(Command::Write),
            0xF5 => Some(Command::EraseWrite),
            0x7E => Some(Command::EraseWriteAlternate),
            0xF2 => Some(Command::ReadBuffer),
            0xF6 => Some(Command::ReadModified),
            0x6E => Some(Command::ReadModifiedAll),
            0x6F => Some(Command::EraseAllUnprotected),
            0xF3 => Some(Command::WriteStructuredField),
            _ => None,
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            Command::Write => 0xF1,
            Command::EraseWrite => 0xF5,
            Command::EraseWriteAlternate => 0x7E,
            Command::ReadBuffer => 0xF2,
            Command::ReadModified => 0xF6,
            Command::ReadModifiedAll => 0x6E,
            Command::EraseAllUnprotected => 0x6F,
            Command::WriteStructuredField => 0xF3,
        }
    }

    /// True when this command erases the buffer before writing.
    pub const fn erases(self) -> bool {
        matches!(self, Command::EraseWrite | Command::EraseWriteAlternate)
    }

    /// True when this command is followed by a Write Control Character.
    pub const fn has_wcc(self) -> bool {
        matches!(
            self,
            Command::Write | Command::EraseWrite | Command::EraseWriteAlternate
        )
    }

    /// True when the host is asking the terminal to send something back.
    pub const fn is_read(self) -> bool {
        matches!(
            self,
            Command::ReadBuffer | Command::ReadModified | Command::ReadModifiedAll
        )
    }

    pub const fn name(self) -> &'static str {
        match self {
            Command::Write => "Write",
            Command::EraseWrite => "EraseWrite",
            Command::EraseWriteAlternate => "EraseWriteAlternate",
            Command::ReadBuffer => "ReadBuffer",
            Command::ReadModified => "ReadModified",
            Command::ReadModifiedAll => "ReadModifiedAll",
            Command::EraseAllUnprotected => "EraseAllUnprotected",
            Command::WriteStructuredField => "WriteStructuredField",
        }
    }
}

impl core::fmt::Display for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// The Write Control Character that follows a write command.
///
/// The top two bits are ignored by the terminal; hosts set them so the byte is
/// a printable graphic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wcc(pub u8);

impl Wcc {
    /// Unlock the keyboard and clear every modified-data-tag: the everyday value.
    pub const DEFAULT: Wcc = Wcc(0xC3);

    /// Reset the partition to its default state.
    pub const fn reset(self) -> bool {
        self.0 & 0x40 != 0
    }

    pub const fn start_printer(self) -> bool {
        self.0 & 0x08 != 0
    }

    /// Ring the terminal bell.
    pub const fn sound_alarm(self) -> bool {
        self.0 & 0x04 != 0
    }

    /// Unlock the keyboard and clear the pending AID.
    ///
    /// This is the bit that tells an automation client the host has finished
    /// and input is allowed again.
    pub const fn keyboard_restore(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Clear the modified-data-tag on every field.
    pub const fn reset_mdt(self) -> bool {
        self.0 & 0x01 != 0
    }
}

/// An order within an outbound data stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Program Tab: advance to the next field.
    Pt,
    /// Graphic Escape: the next byte is from the alternate character set.
    Ge,
    /// Set Buffer Address.
    Sba,
    /// Erase Unprotected to Address.
    Eua,
    /// Insert Cursor.
    Ic,
    /// Start Field.
    Sf,
    /// Set Attribute, for character-level attributes.
    Sa,
    /// Start Field Extended.
    Sfe,
    /// Modify Field.
    Mf,
    /// Repeat to Address.
    Ra,
}

impl Order {
    pub const fn from_byte(byte: u8) -> Option<Order> {
        match byte {
            0x05 => Some(Order::Pt),
            0x08 => Some(Order::Ge),
            0x11 => Some(Order::Sba),
            0x12 => Some(Order::Eua),
            0x13 => Some(Order::Ic),
            0x1D => Some(Order::Sf),
            0x28 => Some(Order::Sa),
            0x29 => Some(Order::Sfe),
            0x2C => Some(Order::Mf),
            0x3C => Some(Order::Ra),
            _ => None,
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            Order::Pt => 0x05,
            Order::Ge => 0x08,
            Order::Sba => 0x11,
            Order::Eua => 0x12,
            Order::Ic => 0x13,
            Order::Sf => 0x1D,
            Order::Sa => 0x28,
            Order::Sfe => 0x29,
            Order::Mf => 0x2C,
            Order::Ra => 0x3C,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Order::Pt => "PT",
            Order::Ge => "GE",
            Order::Sba => "SBA",
            Order::Eua => "EUA",
            Order::Ic => "IC",
            Order::Sf => "SF",
            Order::Sa => "SA",
            Order::Sfe => "SFE",
            Order::Mf => "MF",
            Order::Ra => "RA",
        }
    }
}

/// An Attention Identifier: what the operator did to hand control to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aid {
    /// No AID: the host initiated the read itself.
    None,
    /// Answering a Read Partition with a Query Reply.
    QueryReply,
    Enter,
    /// `PF1` to `PF24`.
    Pf(u8),
    /// `PA1` to `PA3`.
    Pa(u8),
    Clear,
    /// Test Request. Sends `SOH % / STX`, not an ordinary AID record.
    SysReq,
    /// An inbound structured field, such as a Query Reply or file transfer.
    StructuredField,
    /// Selector-pen or cursor-select attention.
    Select,
    Other(u8),
}

#[rustfmt::skip]
const PF_CODES: [u8; 24] = [
    0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0x7A, 0x7B, 0x7C,
    0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0x4A, 0x4B, 0x4C,
];
const PA_CODES: [u8; 3] = [0x6C, 0x6E, 0x6B];

impl Aid {
    pub fn from_byte(byte: u8) -> Aid {
        match byte {
            0x60 => Aid::None,
            0x61 => Aid::QueryReply,
            0x7D => Aid::Enter,
            0x6D => Aid::Clear,
            0xF0 => Aid::SysReq,
            0x88 => Aid::StructuredField,
            0x7E => Aid::Select,
            other => {
                if let Some(i) = PF_CODES.iter().position(|&c| c == other) {
                    Aid::Pf(i as u8 + 1)
                } else if let Some(i) = PA_CODES.iter().position(|&c| c == other) {
                    Aid::Pa(i as u8 + 1)
                } else {
                    Aid::Other(other)
                }
            }
        }
    }

    /// The wire byte, or `None` for an out-of-range `Pf`/`Pa` number.
    pub fn as_byte(self) -> Option<u8> {
        match self {
            Aid::None => Some(0x60),
            Aid::QueryReply => Some(0x61),
            Aid::Enter => Some(0x7D),
            Aid::Clear => Some(0x6D),
            Aid::SysReq => Some(0xF0),
            Aid::StructuredField => Some(0x88),
            Aid::Select => Some(0x7E),
            Aid::Pf(n) => PF_CODES.get(n.checked_sub(1)? as usize).copied(),
            Aid::Pa(n) => PA_CODES.get(n.checked_sub(1)? as usize).copied(),
            Aid::Other(b) => Some(b),
        }
    }

    /// True when this AID produces a **short read**: the AID byte alone, with
    /// no cursor address and no field data.
    ///
    /// Only `CLEAR` and `PA1`-`PA3` behave this way, and a client that sends a
    /// cursor address with them is wrong. Verified against x3270's
    /// `ctlr_read_modified`.
    pub fn is_short_read(self) -> bool {
        matches!(self, Aid::Clear | Aid::Pa(1..=3))
    }

    /// True when the inbound record carries modified field data.
    ///
    /// `SELECT` is the awkward one: it sends the AID and the cursor, but no
    /// fields.
    pub fn sends_field_data(self) -> bool {
        !self.is_short_read() && !matches!(self, Aid::Select | Aid::SysReq)
    }

    /// True when this AID sends a cursor address.
    pub fn sends_cursor(self) -> bool {
        !self.is_short_read() && !matches!(self, Aid::SysReq)
    }

    /// True when pressing this key clears the screen locally, before the host
    /// replies. `CLEAR` resets the buffer to nulls and the cursor to the origin.
    pub fn clears_screen(self) -> bool {
        matches!(self, Aid::Clear)
    }
}

impl core::fmt::Display for Aid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Aid::None => f.write_str("NoAID"),
            Aid::QueryReply => f.write_str("QueryReply"),
            Aid::Enter => f.write_str("Enter"),
            Aid::Pf(n) => write!(f, "PF{n}"),
            Aid::Pa(n) => write!(f, "PA{n}"),
            Aid::Clear => f.write_str("Clear"),
            Aid::SysReq => f.write_str("SysReq"),
            Aid::StructuredField => f.write_str("StructuredField"),
            Aid::Select => f.write_str("Select"),
            Aid::Other(b) => write!(f, "AID(0x{b:02X})"),
        }
    }
}

/// The Test Request record a `SYSREQ` sends: `SOH % / STX` in EBCDIC.
pub const SYSREQ_RECORD: [u8; 4] = [0x01, 0x6C, 0x61, 0x02];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_round_trip() {
        for cmd in [
            Command::Write,
            Command::EraseWrite,
            Command::EraseWriteAlternate,
            Command::ReadBuffer,
            Command::ReadModified,
            Command::ReadModifiedAll,
            Command::EraseAllUnprotected,
            Command::WriteStructuredField,
        ] {
            assert_eq!(Command::from_byte(cmd.as_byte()), Some(cmd));
        }
        assert_eq!(Command::from_byte(0x00), None);
    }

    #[test]
    fn only_erase_write_alternate_selects_the_alternate_size() {
        assert!(Command::EraseWrite.erases());
        assert!(Command::EraseWriteAlternate.erases());
        assert!(!Command::Write.erases());
        assert!(Command::Write.has_wcc());
        assert!(!Command::ReadBuffer.has_wcc());
        assert!(Command::ReadModified.is_read());
    }

    #[test]
    fn wcc_bits_decode() {
        let w = Wcc::DEFAULT;
        assert!(w.reset() && w.keyboard_restore() && w.reset_mdt());
        assert!(!w.sound_alarm());
        assert!(Wcc(0xC7).sound_alarm());
        assert!(!Wcc(0xC0).keyboard_restore());
    }

    #[test]
    fn orders_round_trip() {
        for order in [
            Order::Pt,
            Order::Ge,
            Order::Sba,
            Order::Eua,
            Order::Ic,
            Order::Sf,
            Order::Sa,
            Order::Sfe,
            Order::Mf,
            Order::Ra,
        ] {
            assert_eq!(Order::from_byte(order.as_byte()), Some(order));
        }
        assert_eq!(Order::from_byte(0x40), None, "a space is not an order");
    }

    #[test]
    fn every_pf_and_pa_key_round_trips() {
        for n in 1..=24u8 {
            let aid = Aid::Pf(n);
            let byte = aid.as_byte().expect("PF in range");
            assert_eq!(Aid::from_byte(byte), aid, "PF{n}");
        }
        for n in 1..=3u8 {
            let aid = Aid::Pa(n);
            let byte = aid.as_byte().expect("PA in range");
            assert_eq!(Aid::from_byte(byte), aid, "PA{n}");
        }
        assert_eq!(Aid::Pf(0).as_byte(), None);
        assert_eq!(Aid::Pf(25).as_byte(), None);
        assert_eq!(Aid::Pa(4).as_byte(), None);
    }

    #[test]
    fn pf_codes_match_the_reference_values() {
        assert_eq!(Aid::Pf(1).as_byte(), Some(0xF1));
        assert_eq!(Aid::Pf(3).as_byte(), Some(0xF3));
        assert_eq!(Aid::Pf(10).as_byte(), Some(0x7A));
        assert_eq!(Aid::Pf(12).as_byte(), Some(0x7C));
        assert_eq!(Aid::Pf(13).as_byte(), Some(0xC1));
        assert_eq!(Aid::Pf(24).as_byte(), Some(0x4C));
        assert_eq!(Aid::Pa(1).as_byte(), Some(0x6C));
        assert_eq!(Aid::Pa(2).as_byte(), Some(0x6E));
        assert_eq!(Aid::Pa(3).as_byte(), Some(0x6B));
        assert_eq!(Aid::Enter.as_byte(), Some(0x7D));
        assert_eq!(Aid::Clear.as_byte(), Some(0x6D));
    }

    #[test]
    fn short_read_applies_only_to_clear_and_the_pa_keys() {
        assert!(Aid::Clear.is_short_read());
        assert!(Aid::Pa(1).is_short_read());
        assert!(Aid::Pa(3).is_short_read());
        assert!(!Aid::Enter.is_short_read());
        assert!(!Aid::Pf(3).is_short_read());
        assert!(!Aid::Select.is_short_read());

        // Short reads send neither cursor nor fields.
        assert!(!Aid::Clear.sends_cursor());
        assert!(!Aid::Clear.sends_field_data());
        // SELECT sends a cursor but no field data.
        assert!(Aid::Select.sends_cursor());
        assert!(!Aid::Select.sends_field_data());
        // An ordinary AID sends both.
        assert!(Aid::Enter.sends_cursor() && Aid::Enter.sends_field_data());
    }

    #[test]
    fn display_names_are_stable() {
        assert_eq!(Aid::Pf(7).to_string(), "PF7");
        assert_eq!(Aid::Pa(2).to_string(), "PA2");
        assert_eq!(Aid::Enter.to_string(), "Enter");
        assert_eq!(Aid::Other(0x99).to_string(), "AID(0x99)");
        assert_eq!(
            Command::EraseWriteAlternate.to_string(),
            "EraseWriteAlternate"
        );
    }
}
