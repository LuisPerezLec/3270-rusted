//! TN3270E (RFC 2355) and basic TN3270 (RFC 1576) negotiation, client side.
//!
//! TN3270E is not a mid-session upgrade. The host offers `DO TN3270E` within
//! the first few bytes; if the client accepts, `DEVICE-TYPE` and `FUNCTIONS`
//! are sub-negotiated and every record thereafter carries a 5-byte header. If
//! the client declines, or the host never offers it, the session falls back to
//! `TERMINAL-TYPE` + `BINARY` + `EOR` with no header at all.
//!
//! Both paths are implemented here, because a client that handles only one
//! works against only some hosts.

use std::collections::BTreeSet;

use crate::screen::Model;
use crate::telnet::{
    self, Frame, Verb, OPT_BINARY, OPT_EOR, OPT_TERMINAL_TYPE, OPT_TN3270E, TT_IS, TT_SEND,
};

// ------------------------------------------- TN3270E subnegotiation codes --
const ASSOCIATE: u8 = 0x00;
const CONNECT: u8 = 0x01;
const DEVICE_TYPE: u8 = 0x02;
const FUNCTIONS: u8 = 0x03;
const IS: u8 = 0x04;
const REASON: u8 = 0x05;
const REJECT: u8 = 0x06;
const REQUEST: u8 = 0x07;
const SEND: u8 = 0x08;

/// Why the host refused a device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    ConnPartner,
    DeviceInUse,
    InvAssociate,
    /// The requested LU name is not known to the host.
    InvName,
    /// The host does not serve this model.
    InvDeviceType,
    TypeNameError,
    UnknownError,
    UnsupportedReq,
    Other(u8),
}

impl Reason {
    pub const fn from_byte(byte: u8) -> Reason {
        match byte {
            0x00 => Reason::ConnPartner,
            0x01 => Reason::DeviceInUse,
            0x02 => Reason::InvAssociate,
            0x03 => Reason::InvName,
            0x04 => Reason::InvDeviceType,
            0x05 => Reason::TypeNameError,
            0x06 => Reason::UnknownError,
            0x07 => Reason::UnsupportedReq,
            other => Reason::Other(other),
        }
    }
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Reason::ConnPartner => "CONN-PARTNER",
            Reason::DeviceInUse => "DEVICE-IN-USE",
            Reason::InvAssociate => "INV-ASSOCIATE",
            Reason::InvName => "INV-NAME",
            Reason::InvDeviceType => "INV-DEVICE-TYPE",
            Reason::TypeNameError => "TYPE-NAME-ERROR",
            Reason::UnknownError => "UNKNOWN-ERROR",
            Reason::UnsupportedReq => "UNSUPPORTED-REQ",
            Reason::Other(_) => "unknown reason",
        })
    }
}

/// A TN3270E function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Function {
    /// The host may send a BIND image, which can change the screen geometry.
    BindImage,
    DataStreamCtl,
    /// The host may demand a response record for a write.
    Responses,
    ScsCtlCodes,
    /// The client may send a Test Request.
    Sysreq,
    /// Contention resolution, which s3270 requests by default.
    ContentionResolution,
    Other(u8),
}

impl Function {
    pub const fn from_byte(byte: u8) -> Function {
        match byte {
            0x00 => Function::BindImage,
            0x01 => Function::DataStreamCtl,
            0x02 => Function::Responses,
            0x03 => Function::ScsCtlCodes,
            0x04 => Function::Sysreq,
            0x05 => Function::ContentionResolution,
            other => Function::Other(other),
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            Function::BindImage => 0x00,
            Function::DataStreamCtl => 0x01,
            Function::Responses => 0x02,
            Function::ScsCtlCodes => 0x03,
            Function::Sysreq => 0x04,
            Function::ContentionResolution => 0x05,
            Function::Other(b) => b,
        }
    }
}

impl core::fmt::Display for Function {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Function::BindImage => f.write_str("BIND-IMAGE"),
            Function::DataStreamCtl => f.write_str("DATA-STREAM-CTL"),
            Function::Responses => f.write_str("RESPONSES"),
            Function::ScsCtlCodes => f.write_str("SCS-CTL-CODES"),
            Function::Sysreq => f.write_str("SYSREQ"),
            Function::ContentionResolution => f.write_str("CONTENTION-RESOLUTION"),
            Function::Other(b) => write!(f, "function 0x{b:02X}"),
        }
    }
}

/// The kind of payload a TN3270E record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Data3270,
    Scs,
    Response,
    BindImage,
    Unbind,
    Nvt,
    Request,
    SscpLu,
    PrintEoj,
    Other(u8),
}

impl DataType {
    pub const fn from_byte(byte: u8) -> DataType {
        match byte {
            0x00 => DataType::Data3270,
            0x01 => DataType::Scs,
            0x02 => DataType::Response,
            0x03 => DataType::BindImage,
            0x04 => DataType::Unbind,
            0x05 => DataType::Nvt,
            0x06 => DataType::Request,
            0x07 => DataType::SscpLu,
            0x08 => DataType::PrintEoj,
            other => DataType::Other(other),
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            DataType::Data3270 => 0x00,
            DataType::Scs => 0x01,
            DataType::Response => 0x02,
            DataType::BindImage => 0x03,
            DataType::Unbind => 0x04,
            DataType::Nvt => 0x05,
            DataType::Request => 0x06,
            DataType::SscpLu => 0x07,
            DataType::PrintEoj => 0x08,
            DataType::Other(b) => b,
        }
    }
}

/// The 5-byte header on every TN3270E data record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub data_type: DataType,
    pub request_flag: u8,
    pub response_flag: u8,
    pub seq: u16,
}

/// Response flag: no response wanted.
pub const NO_RESPONSE: u8 = 0x00;
/// Response flag: respond only on error.
pub const ERROR_RESPONSE: u8 = 0x01;
/// Response flag: always respond. Ignoring this can stall the host.
pub const ALWAYS_RESPONSE: u8 = 0x02;

impl Header {
    pub const LEN: usize = 5;

    pub fn new(data_type: DataType, seq: u16) -> Header {
        Header {
            data_type,
            request_flag: 0,
            response_flag: NO_RESPONSE,
            seq,
        }
    }

    pub fn decode(data: &[u8]) -> Option<(Header, &[u8])> {
        if data.len() < Self::LEN {
            return None;
        }
        let header = Header {
            data_type: DataType::from_byte(data[0]),
            request_flag: data[1],
            response_flag: data[2],
            seq: u16::from_be_bytes([data[3], data[4]]),
        };
        Some((header, &data[Self::LEN..]))
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let [s0, s1] = self.seq.to_be_bytes();
        [
            self.data_type.as_byte(),
            self.request_flag,
            self.response_flag,
            s0,
            s1,
        ]
    }

    /// True when the host demands a response record for this write.
    pub fn wants_response(&self) -> bool {
        self.response_flag == ALWAYS_RESPONSE
    }
}

/// A device type, as negotiated: `IBM-3278-4-E` and friends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceType {
    pub model: Model,
    /// The `-E` suffix: extended attributes and structured fields.
    pub extended: bool,
    /// 3279 rather than 3278: a colour terminal.
    pub color: bool,
}

impl Default for DeviceType {
    fn default() -> Self {
        // A colour, extended model 2: the safest thing to ask any host for.
        DeviceType {
            model: Model::Model2,
            extended: true,
            color: true,
        }
    }
}

impl DeviceType {
    pub fn new(model: Model) -> Self {
        DeviceType {
            model,
            extended: true,
            color: true,
        }
    }

    /// Parse a device type name, returning `None` if it is not one we serve.
    pub fn parse(name: &str) -> Option<DeviceType> {
        let upper = name.trim().to_ascii_uppercase();
        let (body, extended) = match upper.strip_suffix("-E") {
            Some(rest) => (rest.to_string(), true),
            None => (upper, false),
        };
        let rest = body.strip_prefix("IBM-")?;
        let (base, model) = rest.split_once('-')?;
        let color = match base {
            "3279" => true,
            "3278" => false,
            _ => return None,
        };
        let model = Model::from_number(model.parse::<u8>().ok()?)?;
        Some(DeviceType {
            model,
            extended,
            color,
        })
    }
}

impl core::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "IBM-{}-{}{}",
            if self.color { "3279" } else { "3278" },
            self.model.number(),
            if self.extended { "-E" } else { "" }
        )
    }
}

/// How far negotiation has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Line mode. Some hosts show a session manager here before 3270 starts.
    #[default]
    Nvt,
    /// Basic TN3270, RFC 1576: no record header.
    Tn3270,
    /// TN3270E, RFC 2355: every record carries a 5-byte header.
    Tn3270e,
}

impl Mode {
    /// True once 3270 records are flowing, in either dialect.
    pub fn is_3270(self) -> bool {
        !matches!(self, Mode::Nvt)
    }
}

/// A BIND image, which can redefine the screen geometry mid-session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindImage {
    pub primary_rows: u16,
    pub primary_cols: u16,
    pub alternate_rows: u16,
    pub alternate_cols: u16,
}

/// Parse a BIND image.
///
/// Byte 24 is the descriptor that decides how bytes 20 to 23 are read, and it
/// is the one that catches people out: `0x7E` forces the alternate size equal
/// to the default, while `0x7F` honours a distinct alternate size. Offsets
/// verified against x3270's `process_bind`.
pub fn parse_bind(data: &[u8]) -> Option<BindImage> {
    if data.first() != Some(&0x31) || data.len() <= 24 {
        return None;
    }
    let (rd, cd) = (u16::from(data[20]), u16::from(data[21]));
    let (ra, ca) = (u16::from(data[22]), u16::from(data[23]));
    let (primary, alternate) = match data[24] {
        0x00 | 0x02 => ((24, 80), (24, 80)),
        // Alternate is whatever the terminal's own maximum is: leave it to the
        // caller by reporting the default for both.
        0x03 => ((24, 80), (0, 0)),
        0x7E => ((rd, cd), (rd, cd)),
        0x7F => ((rd, cd), (ra, ca)),
        _ => return None,
    };
    Some(BindImage {
        primary_rows: primary.0,
        primary_cols: primary.1,
        alternate_rows: alternate.0,
        alternate_cols: alternate.1,
    })
}

/// The PLU name a BIND image carries, if any.
pub fn bind_plu_name(data: &[u8], code_page: crate::ebcdic::CodePage) -> Option<String> {
    let len = usize::from(*data.get(27)?).min(8);
    if len == 0 || data.len() <= 28 + len {
        return None;
    }
    Some(code_page.decode_lossy(&data[28..28 + len], '?'))
}

/// What a client asks for during negotiation.
#[derive(Debug, Clone)]
pub struct Config {
    pub device_type: DeviceType,
    /// An LU name to request. Optional: most hosts assign one.
    pub lu: Option<String>,
    /// Set false to refuse TN3270E and force the RFC 1576 path.
    pub allow_tn3270e: bool,
    /// Functions to request, in preference order.
    pub functions: Vec<Function>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            device_type: DeviceType::default(),
            lu: None,
            allow_tn3270e: true,
            functions: vec![Function::BindImage, Function::Responses, Function::Sysreq],
        }
    }
}

/// Something worth telling the caller about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiated {
    /// Negotiation finished; 3270 records may now flow.
    Ready {
        mode: Mode,
        device_type: DeviceType,
        lu: Option<String>,
        functions: Vec<Function>,
    },
    /// The host refused the requested device type.
    DeviceRejected(Reason),
    /// The host offered TN3270E and the client declined, as configured.
    Tn3270eDeclined,
}

/// The negotiation state machine.
#[derive(Debug)]
pub struct Negotiator {
    config: Config,
    mode: Mode,
    /// Options we have agreed to perform.
    us: BTreeSet<u8>,
    /// Options the peer performs.
    him: BTreeSet<u8>,
    will_sent: BTreeSet<u8>,
    do_sent: BTreeSet<u8>,
    device_type: Option<DeviceType>,
    lu: Option<String>,
    functions: Vec<Function>,
    terminal_type_sent: bool,
    ready: bool,
}

impl Negotiator {
    pub fn new(config: Config) -> Self {
        Negotiator {
            config,
            mode: Mode::Nvt,
            us: BTreeSet::new(),
            him: BTreeSet::new(),
            will_sent: BTreeSet::new(),
            do_sent: BTreeSet::new(),
            device_type: None,
            lu: None,
            functions: Vec::new(),
            terminal_type_sent: false,
            ready: false,
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn device_type(&self) -> DeviceType {
        self.device_type.unwrap_or(self.config.device_type)
    }

    pub fn lu(&self) -> Option<&str> {
        self.lu.as_deref()
    }

    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    /// True when the negotiated function set includes `function`.
    pub fn has_function(&self, function: Function) -> bool {
        self.functions.contains(&function)
    }

    /// Handle one telnet frame, appending any reply to `out`.
    pub fn handle(&mut self, frame: &Frame, out: &mut Vec<u8>) -> Option<Negotiated> {
        match frame {
            Frame::Command { verb, option } => self.on_command(*verb, *option, out),
            Frame::Subnegotiation(body) => self.on_subnegotiation(body, out),
            _ => None,
        }
    }

    fn can_perform(&self, option: u8) -> bool {
        match option {
            OPT_BINARY | OPT_EOR | OPT_TERMINAL_TYPE => true,
            OPT_TN3270E => self.config.allow_tn3270e,
            _ => false,
        }
    }

    fn wants_peer_to(&self, option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_EOR)
    }

    fn on_command(&mut self, verb: Verb, option: u8, out: &mut Vec<u8>) -> Option<Negotiated> {
        match verb {
            Verb::Do => {
                if self.can_perform(option) {
                    if self.will_sent.insert(option) {
                        out.extend_from_slice(&telnet::command(Verb::Will, option));
                    }
                    self.us.insert(option);
                    if option == OPT_EOR || option == OPT_BINARY {
                        // Mirror the option back so records flow both ways.
                        if self.wants_peer_to(option) && self.do_sent.insert(option) {
                            out.extend_from_slice(&telnet::command(Verb::Do, option));
                        }
                        return self.check_basic_ready();
                    }
                } else {
                    out.extend_from_slice(&telnet::command(Verb::Wont, option));
                    if option == OPT_TN3270E {
                        return Some(Negotiated::Tn3270eDeclined);
                    }
                }
            }
            Verb::Will => {
                if self.wants_peer_to(option) {
                    if self.do_sent.insert(option) {
                        out.extend_from_slice(&telnet::command(Verb::Do, option));
                    }
                    self.him.insert(option);
                    return self.check_basic_ready();
                }
                out.extend_from_slice(&telnet::command(Verb::Dont, option));
            }
            Verb::Dont => {
                if self.us.remove(&option) {
                    out.extend_from_slice(&telnet::command(Verb::Wont, option));
                }
            }
            Verb::Wont => {
                if self.him.remove(&option) {
                    out.extend_from_slice(&telnet::command(Verb::Dont, option));
                }
            }
        }
        None
    }

    fn on_subnegotiation(&mut self, body: &[u8], out: &mut Vec<u8>) -> Option<Negotiated> {
        match *body.first()? {
            OPT_TERMINAL_TYPE => {
                if body.get(1) == Some(&TT_SEND) {
                    let name = self.config.device_type.to_string();
                    let mut sb = vec![TT_IS];
                    sb.extend_from_slice(name.as_bytes());
                    out.extend_from_slice(&telnet::subnegotiation(OPT_TERMINAL_TYPE, &sb));
                    self.terminal_type_sent = true;
                    self.device_type = Some(self.config.device_type);
                    // Deliberately do NOT offer BINARY and EOR here. Sending an
                    // unsolicited DO is legal telnet, but Hercules stops
                    // negotiating when it arrives, and a real MVS host is the
                    // authority on what is safe. The host drives this exchange:
                    // it sends DO and WILL for both options, and we answer.
                }
                None
            }
            OPT_TN3270E => self.on_tn3270e(&body[1..], out),
            _ => None,
        }
    }

    fn on_tn3270e(&mut self, body: &[u8], out: &mut Vec<u8>) -> Option<Negotiated> {
        match (*body.first()?, body.get(1)) {
            (SEND, Some(&DEVICE_TYPE)) => {
                let name = self.config.device_type.to_string();
                let mut sb = vec![DEVICE_TYPE, REQUEST];
                sb.extend_from_slice(name.as_bytes());
                if let Some(lu) = &self.config.lu {
                    sb.push(CONNECT);
                    sb.extend_from_slice(lu.as_bytes());
                }
                out.extend_from_slice(&telnet::subnegotiation(OPT_TN3270E, &sb));
                None
            }
            (DEVICE_TYPE, Some(&IS)) => {
                let tail = &body[2..];
                // <device-type> [ CONNECT | ASSOCIATE <lu> ]
                let split = tail.iter().position(|&b| b == CONNECT || b == ASSOCIATE);
                let (name_bytes, lu_bytes) = match split {
                    Some(i) => (&tail[..i], Some(&tail[i + 1..])),
                    None => (tail, None),
                };
                let name = String::from_utf8_lossy(name_bytes).trim().to_string();
                self.device_type = DeviceType::parse(&name);
                self.lu = lu_bytes
                    .map(|b| String::from_utf8_lossy(b).trim().to_string())
                    .filter(|s| !s.is_empty());

                let mut sb = vec![FUNCTIONS, REQUEST];
                sb.extend(self.config.functions.iter().map(|f| f.as_byte()));
                out.extend_from_slice(&telnet::subnegotiation(OPT_TN3270E, &sb));
                None
            }
            (DEVICE_TYPE, Some(&REJECT)) => {
                let reason = if body.get(2) == Some(&REASON) {
                    body.get(3).copied().map(Reason::from_byte)
                } else {
                    None
                };
                Some(Negotiated::DeviceRejected(
                    reason.unwrap_or(Reason::UnknownError),
                ))
            }
            (FUNCTIONS, Some(&IS)) => {
                self.functions = body[2..].iter().map(|&b| Function::from_byte(b)).collect();
                self.finish(Mode::Tn3270e)
            }
            (FUNCTIONS, Some(&REQUEST)) => {
                // The host is counter-offering a subset; accept it.
                let offered: Vec<Function> =
                    body[2..].iter().map(|&b| Function::from_byte(b)).collect();
                let mut sb = vec![FUNCTIONS, IS];
                sb.extend(offered.iter().map(|f| f.as_byte()));
                out.extend_from_slice(&telnet::subnegotiation(OPT_TN3270E, &sb));
                self.functions = offered;
                self.finish(Mode::Tn3270e)
            }
            _ => None,
        }
    }

    fn check_basic_ready(&mut self) -> Option<Negotiated> {
        if self.ready || !self.terminal_type_sent {
            return None;
        }
        let needed = [OPT_BINARY, OPT_EOR];
        if needed.iter().all(|o| self.us.contains(o)) && needed.iter().all(|o| self.him.contains(o))
        {
            return self.finish(Mode::Tn3270);
        }
        None
    }

    fn finish(&mut self, mode: Mode) -> Option<Negotiated> {
        if self.ready {
            return None;
        }
        self.ready = true;
        self.mode = mode;
        Some(Negotiated::Ready {
            mode,
            device_type: self.device_type(),
            lu: self.lu.clone(),
            functions: self.functions.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telnet::{Decoder, OPT_TN3270E};

    /// Drive the negotiator with raw host bytes, returning what it replied and
    /// any event it raised.
    fn exchange(neg: &mut Negotiator, host: &[u8]) -> (Vec<u8>, Vec<Negotiated>) {
        let mut decoder = Decoder::new();
        let frames = decoder.decode(host).expect("well-formed");
        let mut out = Vec::new();
        let mut events = Vec::new();
        for frame in &frames {
            if let Some(ev) = neg.handle(frame, &mut out) {
                events.push(ev);
            }
        }
        (out, events)
    }

    #[test]
    fn device_type_names_round_trip() {
        for name in [
            "IBM-3278-2",
            "IBM-3278-2-E",
            "IBM-3279-4-E",
            "IBM-3279-5",
            "IBM-3278-3-E",
        ] {
            let dt = DeviceType::parse(name).expect(name);
            assert_eq!(dt.to_string(), name);
        }
        assert_eq!(DeviceType::parse("IBM-DYNAMIC"), None);
        assert_eq!(DeviceType::parse("IBM-3278-9"), None);
        assert_eq!(DeviceType::parse("nonsense"), None);
        // Case and whitespace are tolerated.
        assert_eq!(
            DeviceType::parse(" ibm-3279-4-e ").map(|d| d.model),
            Some(Model::Model4)
        );
    }

    #[test]
    fn full_tn3270e_negotiation_reaches_ready() {
        let mut neg = Negotiator::new(Config {
            device_type: DeviceType::new(Model::Model4),
            ..Config::default()
        });

        // Host offers TN3270E.
        let (reply, events) = exchange(&mut neg, &telnet::command(Verb::Do, OPT_TN3270E));
        assert_eq!(reply, telnet::command(Verb::Will, OPT_TN3270E).to_vec());
        assert!(events.is_empty());

        // Host asks for the device type.
        let (reply, _) = exchange(
            &mut neg,
            &telnet::subnegotiation(OPT_TN3270E, &[SEND, DEVICE_TYPE]),
        );
        let expected = {
            let mut sb = vec![DEVICE_TYPE, REQUEST];
            sb.extend_from_slice(b"IBM-3279-4-E");
            telnet::subnegotiation(OPT_TN3270E, &sb)
        };
        assert_eq!(reply, expected);

        // Host accepts and names the LU.
        let mut sb = vec![DEVICE_TYPE, IS];
        sb.extend_from_slice(b"IBM-3279-4-E");
        sb.push(CONNECT);
        sb.extend_from_slice(b"TESTLU01");
        let (reply, _) = exchange(&mut neg, &telnet::subnegotiation(OPT_TN3270E, &sb));
        assert_eq!(neg.lu(), Some("TESTLU01"));
        // We now request functions.
        assert!(reply.windows(2).any(|w| w == [FUNCTIONS, REQUEST]));

        // Host agrees to all of them.
        let (_, events) = exchange(
            &mut neg,
            &telnet::subnegotiation(
                OPT_TN3270E,
                &[
                    FUNCTIONS,
                    IS,
                    Function::BindImage.as_byte(),
                    Function::Responses.as_byte(),
                    Function::Sysreq.as_byte(),
                ],
            ),
        );
        assert!(neg.is_ready());
        assert_eq!(neg.mode(), Mode::Tn3270e);
        assert_eq!(neg.device_type().model, Model::Model4);
        assert!(neg.has_function(Function::BindImage));
        assert!(matches!(
            events.first(),
            Some(Negotiated::Ready {
                mode: Mode::Tn3270e,
                ..
            })
        ));
    }

    #[test]
    fn a_function_counter_offer_is_accepted() {
        let mut neg = Negotiator::new(Config::default());
        exchange(&mut neg, &telnet::command(Verb::Do, OPT_TN3270E));
        exchange(
            &mut neg,
            &telnet::subnegotiation(OPT_TN3270E, &[SEND, DEVICE_TYPE]),
        );
        let mut sb = vec![DEVICE_TYPE, IS];
        sb.extend_from_slice(b"IBM-3279-2-E");
        exchange(&mut neg, &telnet::subnegotiation(OPT_TN3270E, &sb));

        // The host drops SYSREQ from the list.
        let (reply, events) = exchange(
            &mut neg,
            &telnet::subnegotiation(
                OPT_TN3270E,
                &[
                    FUNCTIONS,
                    REQUEST,
                    Function::BindImage.as_byte(),
                    Function::Responses.as_byte(),
                ],
            ),
        );
        // We answer IS with exactly what was offered.
        assert!(reply.windows(2).any(|w| w == [FUNCTIONS, IS]));
        assert_eq!(neg.functions(), &[Function::BindImage, Function::Responses]);
        assert!(!neg.has_function(Function::Sysreq));
        assert!(matches!(events.first(), Some(Negotiated::Ready { .. })));
    }

    #[test]
    fn declining_tn3270e_falls_back_to_the_basic_path() {
        let mut neg = Negotiator::new(Config {
            allow_tn3270e: false,
            device_type: DeviceType::new(Model::Model2),
            ..Config::default()
        });

        let (reply, events) = exchange(&mut neg, &telnet::command(Verb::Do, OPT_TN3270E));
        assert_eq!(reply, telnet::command(Verb::Wont, OPT_TN3270E).to_vec());
        assert_eq!(events, vec![Negotiated::Tn3270eDeclined]);

        // Host falls back to TERMINAL-TYPE.
        let (reply, _) = exchange(&mut neg, &telnet::command(Verb::Do, OPT_TERMINAL_TYPE));
        assert_eq!(
            reply,
            telnet::command(Verb::Will, OPT_TERMINAL_TYPE).to_vec()
        );

        let (reply, _) = exchange(
            &mut neg,
            &telnet::subnegotiation(OPT_TERMINAL_TYPE, &[TT_SEND]),
        );
        assert!(
            reply.windows(12).any(|w| w == b"IBM-3279-2-E"),
            "terminal type must be sent"
        );

        // Host turns on BINARY and EOR in both directions.
        let mut host = Vec::new();
        for opt in [OPT_EOR, OPT_BINARY] {
            host.extend_from_slice(&telnet::command(Verb::Do, opt));
            host.extend_from_slice(&telnet::command(Verb::Will, opt));
        }
        let (_, events) = exchange(&mut neg, &host);
        assert!(neg.is_ready());
        assert_eq!(neg.mode(), Mode::Tn3270, "the basic dialect, no header");
        assert!(matches!(
            events.last(),
            Some(Negotiated::Ready {
                mode: Mode::Tn3270,
                ..
            })
        ));
    }

    #[test]
    fn the_client_never_offers_binary_or_eor_unsolicited() {
        // Regression guard. Sending DO BINARY / DO EOR straight after the
        // TERMINAL-TYPE IS is legal telnet, but Hercules running MVS 3.8j stops
        // negotiating when it arrives, and the session hangs. Only ever answer
        // what the host offers.
        let mut neg = Negotiator::new(Config {
            allow_tn3270e: false,
            ..Config::default()
        });
        exchange(&mut neg, &telnet::command(Verb::Do, OPT_TERMINAL_TYPE));
        let (reply, _) = exchange(
            &mut neg,
            &telnet::subnegotiation(OPT_TERMINAL_TYPE, &[TT_SEND]),
        );

        // The reply must be the terminal type and nothing else.
        let unsolicited = telnet::command(Verb::Do, OPT_EOR);
        assert!(
            !reply.windows(3).any(|w| w == unsolicited),
            "must not offer DO EOR before the host asks: {reply:02x?}"
        );
        let unsolicited = telnet::command(Verb::Do, OPT_BINARY);
        assert!(
            !reply.windows(3).any(|w| w == unsolicited),
            "must not offer DO BINARY before the host asks: {reply:02x?}"
        );
        assert!(!neg.is_ready(), "not ready until BINARY and EOR are agreed");
    }

    #[test]
    fn a_rejected_device_type_is_reported_with_its_reason() {
        let mut neg = Negotiator::new(Config::default());
        exchange(&mut neg, &telnet::command(Verb::Do, OPT_TN3270E));
        let (_, events) = exchange(
            &mut neg,
            &telnet::subnegotiation(OPT_TN3270E, &[DEVICE_TYPE, REJECT, REASON, 0x04]),
        );
        assert_eq!(
            events,
            vec![Negotiated::DeviceRejected(Reason::InvDeviceType)]
        );
        assert!(!neg.is_ready());
    }

    #[test]
    fn negotiation_does_not_loop_on_repeated_offers() {
        let mut neg = Negotiator::new(Config::default());
        let (first, _) = exchange(&mut neg, &telnet::command(Verb::Do, OPT_EOR));
        let (second, _) = exchange(&mut neg, &telnet::command(Verb::Do, OPT_EOR));
        assert!(!first.is_empty());
        assert!(
            second.is_empty(),
            "an option already agreed must not be answered again"
        );
    }

    #[test]
    fn unsupported_options_are_refused() {
        let mut neg = Negotiator::new(Config::default());
        let (reply, _) = exchange(&mut neg, &telnet::command(Verb::Do, telnet::OPT_ECHO));
        assert_eq!(
            reply,
            telnet::command(Verb::Wont, telnet::OPT_ECHO).to_vec()
        );
        let (reply, _) = exchange(&mut neg, &telnet::command(Verb::Will, telnet::OPT_ECHO));
        assert_eq!(
            reply,
            telnet::command(Verb::Dont, telnet::OPT_ECHO).to_vec()
        );
    }

    #[test]
    fn headers_round_trip() {
        let h = Header {
            data_type: DataType::Data3270,
            request_flag: 0,
            response_flag: ALWAYS_RESPONSE,
            seq: 0x1234,
        };
        let bytes = h.encode();
        assert_eq!(bytes, [0x00, 0x00, 0x02, 0x12, 0x34]);
        let (back, rest) = Header::decode(&[0x00, 0x00, 0x02, 0x12, 0x34, 0xF5]).unwrap();
        assert_eq!(back, h);
        assert_eq!(rest, &[0xF5]);
        assert!(back.wants_response());
        assert!(Header::decode(&[0x00, 0x00]).is_none());
    }

    #[test]
    fn bind_images_are_read_with_the_verified_offsets() {
        let mut bind = vec![0u8; 37];
        bind[0] = 0x31;
        bind[20] = 24;
        bind[21] = 80;
        bind[22] = 43;
        bind[23] = 80;

        // 0x7F honours a distinct alternate size.
        bind[24] = 0x7F;
        assert_eq!(
            parse_bind(&bind),
            Some(BindImage {
                primary_rows: 24,
                primary_cols: 80,
                alternate_rows: 43,
                alternate_cols: 80
            })
        );

        // 0x7E forces the alternate size equal to the default. This is the
        // byte that silently clamps a model 4 back to 24x80.
        bind[24] = 0x7E;
        let clamped = parse_bind(&bind).unwrap();
        assert_eq!((clamped.alternate_rows, clamped.alternate_cols), (24, 80));

        // 0x00 and 0x02 mean both sizes are 24x80 regardless of 20..23.
        bind[24] = 0x02;
        let fixed = parse_bind(&bind).unwrap();
        assert_eq!((fixed.alternate_rows, fixed.alternate_cols), (24, 80));

        // Not a BIND RU.
        assert_eq!(parse_bind(&[0x01, 0x02]), None);
    }

    #[test]
    fn a_bind_image_plu_name_is_decoded() {
        let mut bind = vec![0u8; 28];
        bind[0] = 0x31;
        bind[24] = 0x7F;
        bind[27] = 8;
        bind.extend_from_slice(&crate::ebcdic::CP037.encode_lossy("TESTLU01", 0x6F));
        bind.push(0x00); // the reference requires one byte past the name
        assert_eq!(
            bind_plu_name(&bind, crate::ebcdic::CP037).as_deref(),
            Some("TESTLU01")
        );
    }

    #[test]
    fn mode_reports_whether_3270_records_are_flowing() {
        assert!(!Mode::Nvt.is_3270());
        assert!(Mode::Tn3270.is_3270());
        assert!(Mode::Tn3270e.is_3270());
    }
}
