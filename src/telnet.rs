//! Telnet framing: IAC escaping, record boundaries, subnegotiation.
//!
//! This layer knows nothing about 3270. It turns a byte stream into
//! [`Frame`]s and back.
//!
//! One subtlety drives the API shape. In 3270 mode a record ends at
//! `IAC EOR`, so a record split across two reads must be held until the
//! terminator arrives. In NVT (line) mode there is no terminator at all, and
//! data is simply data. The decoder therefore never guesses: it emits
//! [`Frame::Record`] only on `IAC EOR`, and leaves anything else in a pending
//! buffer that the caller drains with [`Decoder::take_pending`] *only* when it
//! knows the session is still in NVT mode.

/// Interpret As Command.
pub const IAC: u8 = 0xFF;
pub const DONT: u8 = 0xFE;
pub const DO: u8 = 0xFD;
pub const WONT: u8 = 0xFC;
pub const WILL: u8 = 0xFB;
/// Begin subnegotiation.
pub const SB: u8 = 0xFA;
/// End subnegotiation.
pub const SE: u8 = 0xF0;
/// End of record, the 3270 record terminator.
pub const EOR: u8 = 0xEF;
pub const NOP: u8 = 0xF1;

/// Telnet option: transmit binary.
pub const OPT_BINARY: u8 = 0x00;
pub const OPT_ECHO: u8 = 0x01;
pub const OPT_SUPPRESS_GO_AHEAD: u8 = 0x03;
pub const OPT_TERMINAL_TYPE: u8 = 0x18;
/// Telnet option: end of record.
pub const OPT_EOR: u8 = 0x19;
/// Telnet option: TN3270E (RFC 2355).
pub const OPT_TN3270E: u8 = 0x28;

/// TERMINAL-TYPE subnegotiation: `IS`.
pub const TT_IS: u8 = 0x00;
/// TERMINAL-TYPE subnegotiation: `SEND`.
pub const TT_SEND: u8 = 0x01;

/// The name of a telnet option, for tracing.
pub fn option_name(option: u8) -> &'static str {
    match option {
        OPT_BINARY => "BINARY",
        OPT_ECHO => "ECHO",
        OPT_SUPPRESS_GO_AHEAD => "SUPPRESS-GO-AHEAD",
        OPT_TERMINAL_TYPE => "TERMINAL-TYPE",
        OPT_EOR => "EOR",
        OPT_TN3270E => "TN3270E",
        _ => "unknown",
    }
}

/// A negotiation verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    Do,
    Dont,
    Will,
    Wont,
}

impl Verb {
    /// The wire byte for this verb.
    pub const fn as_byte(self) -> u8 {
        match self {
            Verb::Do => DO,
            Verb::Dont => DONT,
            Verb::Will => WILL,
            Verb::Wont => WONT,
        }
    }

    /// Parse a wire byte, if it is a negotiation verb.
    pub const fn from_byte(byte: u8) -> Option<Verb> {
        match byte {
            DO => Some(Verb::Do),
            DONT => Some(Verb::Dont),
            WILL => Some(Verb::Will),
            WONT => Some(Verb::Wont),
            _ => None,
        }
    }

    /// The verb that answers this one in the negative.
    pub const fn refusal(self) -> Verb {
        match self {
            Verb::Do | Verb::Dont => Verb::Wont,
            Verb::Will | Verb::Wont => Verb::Dont,
        }
    }
}

impl core::fmt::Display for Verb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Verb::Do => "DO",
            Verb::Dont => "DONT",
            Verb::Will => "WILL",
            Verb::Wont => "WONT",
        })
    }
}

/// One item recovered from the inbound byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A complete 3270 record, IAC-unescaped, that was terminated by `IAC EOR`.
    Record(Vec<u8>),
    /// Option negotiation.
    Command { verb: Verb, option: u8 },
    /// A complete subnegotiation body, IAC-unescaped. The first byte is the
    /// option being negotiated.
    Subnegotiation(Vec<u8>),
    /// A telnet command with no option, such as `NOP`.
    Signal(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Data,
    Iac,
    Verb(Verb),
    Sb,
    SbIac,
}

/// Incremental telnet stream decoder.
///
/// Feed it whatever arrives from the socket, in any chunking; frames come out
/// whole.
#[derive(Debug)]
pub struct Decoder {
    state: State,
    /// Data bytes seen since the last record boundary.
    pending: Vec<u8>,
    subneg: Vec<u8>,
    max_record: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// A decoder with a 64 KiB cap on a single record.
    pub fn new() -> Self {
        Self::with_max_record(64 * 1024)
    }

    /// A decoder that refuses to buffer a record larger than `max_record`,
    /// so a peer cannot force unbounded allocation.
    pub fn with_max_record(max_record: usize) -> Self {
        Decoder {
            state: State::Data,
            pending: Vec::new(),
            subneg: Vec::new(),
            max_record,
        }
    }

    /// Feed bytes, appending any completed frames to `out`.
    ///
    /// Returns an error only if a record or subnegotiation exceeded the
    /// configured limit; the decoder is left resynchronised at the next
    /// record boundary.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Frame>) -> Result<(), Overflow> {
        let mut overflowed = false;
        for &byte in data {
            match self.state {
                State::Data => {
                    if byte == IAC {
                        self.state = State::Iac;
                    } else if self.pending.len() < self.max_record {
                        self.pending.push(byte);
                    } else {
                        overflowed = true;
                    }
                }
                State::Iac => match byte {
                    // A doubled IAC is one literal 0xFF.
                    IAC => {
                        if self.pending.len() < self.max_record {
                            self.pending.push(IAC);
                        } else {
                            overflowed = true;
                        }
                        self.state = State::Data;
                    }
                    EOR => {
                        out.push(Frame::Record(core::mem::take(&mut self.pending)));
                        self.state = State::Data;
                    }
                    SB => {
                        self.subneg.clear();
                        self.state = State::Sb;
                    }
                    other => {
                        if let Some(verb) = Verb::from_byte(other) {
                            self.state = State::Verb(verb);
                        } else {
                            out.push(Frame::Signal(other));
                            self.state = State::Data;
                        }
                    }
                },
                State::Verb(verb) => {
                    out.push(Frame::Command { verb, option: byte });
                    self.state = State::Data;
                }
                State::Sb => {
                    if byte == IAC {
                        self.state = State::SbIac;
                    } else if self.subneg.len() < self.max_record {
                        self.subneg.push(byte);
                    } else {
                        overflowed = true;
                    }
                }
                State::SbIac => match byte {
                    IAC => {
                        self.subneg.push(IAC);
                        self.state = State::Sb;
                    }
                    SE => {
                        out.push(Frame::Subnegotiation(core::mem::take(&mut self.subneg)));
                        self.state = State::Data;
                    }
                    // Malformed: an unescaped IAC inside SB. Resynchronise
                    // rather than dropping the connection, which is what
                    // established clients do.
                    _ => self.state = State::Sb,
                },
            }
        }
        if overflowed {
            self.pending.clear();
            self.subneg.clear();
            self.state = State::Data;
            return Err(Overflow);
        }
        Ok(())
    }

    /// Convenience wrapper over [`Decoder::feed`] that allocates.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Frame>, Overflow> {
        let mut out = Vec::new();
        self.feed(data, &mut out)?;
        Ok(out)
    }

    /// Bytes buffered but not yet terminated by `IAC EOR`.
    ///
    /// In 3270 mode this is a partial record and must be left alone. Drain it
    /// only while the session is still in NVT mode, where data has no record
    /// terminator.
    pub fn pending(&self) -> &[u8] {
        &self.pending
    }

    /// Take the pending bytes, as NVT data. See [`Decoder::pending`].
    pub fn take_pending(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.pending)
    }

    /// True when no partial frame is buffered.
    pub fn is_idle(&self) -> bool {
        self.state == State::Data && self.pending.is_empty() && self.subneg.is_empty()
    }
}

/// A peer sent a record or subnegotiation larger than the configured limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

impl core::fmt::Display for Overflow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("telnet record exceeded the configured maximum")
    }
}

impl std::error::Error for Overflow {}

// ------------------------------------------------------------------ encode --

/// Double every `IAC` in `payload`, as required inside a record.
pub fn escape_into(payload: &[u8], out: &mut Vec<u8>) {
    for &byte in payload {
        out.push(byte);
        if byte == IAC {
            out.push(IAC);
        }
    }
}

/// Encode one 3270 record: escape `IAC`, then terminate with `IAC EOR`.
pub fn record_into(payload: &[u8], out: &mut Vec<u8>) {
    escape_into(payload, out);
    out.extend_from_slice(&[IAC, EOR]);
}

/// Encode one 3270 record.
pub fn record(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    record_into(payload, &mut out);
    out
}

/// Encode an option negotiation command.
pub fn command(verb: Verb, option: u8) -> [u8; 3] {
    [IAC, verb.as_byte(), option]
}

/// Encode a subnegotiation: `IAC SB <option> <body> IAC SE`.
pub fn subnegotiation_into(option: u8, body: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[IAC, SB, option]);
    escape_into(body, out);
    out.extend_from_slice(&[IAC, SE]);
}

/// Encode a subnegotiation.
pub fn subnegotiation(option: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    subnegotiation_into(option, body, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(chunks: &[&[u8]]) -> Vec<Frame> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        for chunk in chunks {
            d.feed(chunk, &mut out).unwrap();
        }
        out
    }

    #[test]
    fn splits_commands_records_and_subnegotiation() {
        let frames = decode_all(&[&[
            IAC,
            DO,
            OPT_TN3270E,
            0x05,
            0x06,
            IAC,
            EOR,
            IAC,
            SB,
            OPT_TN3270E,
            0x02,
            0x04,
            IAC,
            SE,
        ]]);
        assert_eq!(
            frames,
            vec![
                Frame::Command {
                    verb: Verb::Do,
                    option: OPT_TN3270E
                },
                Frame::Record(vec![0x05, 0x06]),
                Frame::Subnegotiation(vec![OPT_TN3270E, 0x02, 0x04]),
            ]
        );
    }

    #[test]
    fn a_doubled_iac_is_one_literal_byte() {
        let frames = decode_all(&[&[0x01, IAC, IAC, 0x02, IAC, EOR]]);
        assert_eq!(frames, vec![Frame::Record(vec![0x01, 0xFF, 0x02])]);
    }

    #[test]
    fn iac_survives_inside_a_subnegotiation() {
        // A Query Reply carrying colour 0xFF has to escape it.
        let frames = decode_all(&[&[IAC, SB, OPT_TN3270E, 0xFF, 0xFF, 0x01, IAC, SE]]);
        assert_eq!(
            frames,
            vec![Frame::Subnegotiation(vec![OPT_TN3270E, 0xFF, 0x01])]
        );
    }

    #[test]
    fn a_record_split_across_reads_is_not_lost() {
        // The whole reason `pending` is not flushed automatically: every
        // prefix of this record must stay buffered until IAC EOR arrives.
        let whole: Vec<u8> = vec![0xF5, 0xC3, 0x11, 0x40, 0x40, 0x81, IAC, EOR];
        for split in 1..whole.len() {
            let frames = decode_all(&[&whole[..split], &whole[split..]]);
            assert_eq!(
                frames,
                vec![Frame::Record(vec![0xF5, 0xC3, 0x11, 0x40, 0x40, 0x81])],
                "split after {split} bytes"
            );
        }
    }

    #[test]
    fn a_command_split_across_reads_is_not_lost() {
        for split in 1..3 {
            let bytes = [IAC, WILL, OPT_EOR];
            let frames = decode_all(&[&bytes[..split], &bytes[split..]]);
            assert_eq!(
                frames,
                vec![Frame::Command {
                    verb: Verb::Will,
                    option: OPT_EOR
                }]
            );
        }
    }

    #[test]
    fn an_escaped_iac_split_across_reads_is_not_lost() {
        let frames = decode_all(&[&[0x01, IAC], &[IAC, 0x02, IAC], &[EOR]]);
        assert_eq!(frames, vec![Frame::Record(vec![0x01, 0xFF, 0x02])]);
    }

    #[test]
    fn nvt_data_stays_pending_until_drained() {
        let mut d = Decoder::new();
        let frames = d.decode(b"USSMSG10 ENTER APPLICATION\r\n").unwrap();
        assert!(frames.is_empty(), "NVT text is not a record");
        assert_eq!(d.pending(), b"USSMSG10 ENTER APPLICATION\r\n");
        assert_eq!(d.take_pending(), b"USSMSG10 ENTER APPLICATION\r\n");
        assert!(d.is_idle());
    }

    #[test]
    fn unknown_two_byte_commands_surface_as_signals() {
        let frames = decode_all(&[&[IAC, NOP, 0x01, IAC, EOR]]);
        assert_eq!(frames, vec![Frame::Signal(NOP), Frame::Record(vec![0x01])]);
    }

    #[test]
    fn an_oversized_record_errors_and_resynchronises() {
        let mut d = Decoder::with_max_record(8);
        let mut out = Vec::new();
        assert_eq!(d.feed(&[0u8; 32], &mut out), Err(Overflow));
        assert!(d.is_idle(), "decoder should resynchronise after overflow");
        // It keeps working afterwards.
        d.feed(&[0x01, IAC, EOR], &mut out).unwrap();
        assert_eq!(out, vec![Frame::Record(vec![0x01])]);
    }

    #[test]
    fn encoding_round_trips_through_the_decoder() {
        let payload = vec![0xF5, 0xC3, 0xFF, 0x11, 0x5D, 0x7F];
        let wire = record(&payload);
        assert_eq!(&wire[wire.len() - 2..], &[IAC, EOR]);
        let frames = decode_all(&[&wire]);
        assert_eq!(frames, vec![Frame::Record(payload)]);
    }

    #[test]
    fn subnegotiation_round_trips() {
        let body = vec![0x02, 0x07, 0xFF, 0x41];
        let wire = subnegotiation(OPT_TN3270E, &body);
        let frames = decode_all(&[&wire]);
        let mut expected = vec![OPT_TN3270E];
        expected.extend_from_slice(&body);
        assert_eq!(frames, vec![Frame::Subnegotiation(expected)]);
    }

    #[test]
    fn verbs_map_to_and_from_the_wire() {
        for verb in [Verb::Do, Verb::Dont, Verb::Will, Verb::Wont] {
            assert_eq!(Verb::from_byte(verb.as_byte()), Some(verb));
        }
        assert_eq!(Verb::from_byte(IAC), None);
        assert_eq!(Verb::Do.refusal(), Verb::Wont);
        assert_eq!(Verb::Will.refusal(), Verb::Dont);
    }
}
