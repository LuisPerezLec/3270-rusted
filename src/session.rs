//! The sans-IO session: bytes in, events and bytes out.
//!
//! [`Session`] owns the negotiation state machine, the telnet decoder and the
//! screen. It never touches a socket, which means a recorded byte stream is a
//! complete test fixture and the same logic serves any transport.
//!
//! ```no_run
//! use tn3270::{Session, SessionConfig};
//! let mut session = Session::new(SessionConfig::default());
//! session.receive(&[/* bytes from the socket */]);
//! let to_send = session.take_output();      // write these back
//! while let Some(event) = session.next_event() { /* react */ }
//! ```

use std::collections::VecDeque;

use crate::ds::{self, sf, Aid, Command, ParseError};
use crate::ebcdic::{self, CodePage};
use crate::negotiate::{
    self, parse_bind, DataType, DeviceType, Function, Header, Mode, Negotiated, Negotiator, Reason,
    ALWAYS_RESPONSE,
};
use crate::screen::{Model, Screen};
use crate::telnet::{self, Decoder, Frame};

/// Positive response sense code: device end.
const POS_DEVICE_END: u8 = 0x00;

/// How to run a session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub negotiate: negotiate::Config,
    pub code_page: CodePage,
    /// Answer Read Partition (Query) automatically. Hosts commonly wait for
    /// this before painting, so leaving it on is almost always right.
    pub auto_query_reply: bool,
    /// Honour a BIND image's geometry. Turn it off to keep the negotiated
    /// model size regardless of what the host says.
    pub honour_bind_image: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            negotiate: negotiate::Config::default(),
            code_page: ebcdic::DEFAULT,
            auto_query_reply: true,
            honour_bind_image: true,
        }
    }
}

impl SessionConfig {
    /// A configuration for one model, everything else left at its default.
    pub fn model(model: Model) -> Self {
        SessionConfig {
            negotiate: negotiate::Config {
                device_type: DeviceType::new(model),
                ..negotiate::Config::default()
            },
            ..SessionConfig::default()
        }
    }

    /// Request a specific LU name.
    pub fn with_lu(mut self, lu: impl Into<String>) -> Self {
        self.negotiate.lu = Some(lu.into());
        self
    }

    /// Refuse TN3270E, forcing the basic RFC 1576 path.
    pub fn without_tn3270e(mut self) -> Self {
        self.negotiate.allow_tn3270e = false;
        self
    }

    pub fn with_code_page(mut self, code_page: CodePage) -> Self {
        self.code_page = code_page;
        self
    }
}

/// Something the caller may want to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Negotiation finished. 3270 records are now flowing.
    Connected {
        mode: Mode,
        device_type: DeviceType,
        lu: Option<String>,
        functions: Vec<Function>,
    },
    /// The host refused the requested device type.
    DeviceRejected(Reason),
    /// The screen changed.
    ScreenUpdated,
    /// The host unlocked the keyboard, so input is allowed.
    ///
    /// This is the signal to wait for after sending an AID; it is what makes
    /// automation deterministic rather than timing-dependent.
    KeyboardUnlocked,
    /// The host rang the bell.
    Alarm,
    /// The host resized the screen, usually from a BIND image.
    Resized { rows: u16, cols: u16 },
    /// Line-mode text, which a session manager sends before 3270 starts.
    NvtText(String),
    /// Text from the SSCP, such as a VTAM message.
    SscpText(String),
    /// The host unbound the session.
    Unbind,
    /// A record could not be applied. The session stays usable.
    ProtocolError(String),
}

/// A 3270 session.
#[derive(Debug)]
pub struct Session {
    config: SessionConfig,
    decoder: Decoder,
    negotiator: Negotiator,
    screen: Screen,
    out: Vec<u8>,
    events: VecDeque<Event>,
    seq: u16,
    keyboard_locked: bool,
    connected: bool,
}

impl Session {
    pub fn new(config: SessionConfig) -> Self {
        let model = config.negotiate.device_type.model;
        let mut screen = Screen::new(model);
        screen.set_code_page(config.code_page);
        Session {
            config,
            decoder: Decoder::new(),
            negotiator: Negotiator::new(negotiate::Config::default()),
            screen,
            out: Vec::new(),
            events: VecDeque::new(),
            seq: 0,
            // Nothing may be sent until the host says so.
            keyboard_locked: true,
            connected: false,
        }
        .init()
    }

    fn init(mut self) -> Self {
        self.negotiator = Negotiator::new(self.config.negotiate.clone());
        self
    }

    // -------------------------------------------------------------- state --

    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    pub fn mode(&self) -> Mode {
        self.negotiator.mode()
    }

    /// True once negotiation has finished.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// True while the host has the keyboard locked, so no AID may be sent.
    pub fn is_keyboard_locked(&self) -> bool {
        self.keyboard_locked
    }

    pub fn device_type(&self) -> DeviceType {
        self.negotiator.device_type()
    }

    pub fn lu(&self) -> Option<&str> {
        self.negotiator.lu()
    }

    pub fn functions(&self) -> &[Function] {
        self.negotiator.functions()
    }

    /// Bytes that must be written to the peer. Drains the buffer.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    /// True when there is nothing queued to send.
    pub fn output_is_empty(&self) -> bool {
        self.out.is_empty()
    }

    pub fn next_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    // ------------------------------------------------------------ receive --

    /// Feed bytes from the peer.
    pub fn receive(&mut self, data: &[u8]) {
        let mut frames = Vec::new();
        if self.decoder.feed(data, &mut frames).is_err() {
            self.events.push_back(Event::ProtocolError(
                "a record exceeded the maximum size and was discarded".into(),
            ));
        }
        for frame in &frames {
            self.on_frame(frame);
        }
        // Before 3270 framing begins, leftover bytes really are line-mode
        // text. Afterwards they are a partial record and must stay buffered.
        if !self.negotiator.mode().is_3270() && !self.decoder.pending().is_empty() {
            let raw = self.decoder.take_pending();
            let text = String::from_utf8_lossy(&raw).trim().to_string();
            if !text.is_empty() {
                self.events.push_back(Event::NvtText(text));
            }
        }
    }

    fn on_frame(&mut self, frame: &Frame) {
        match frame {
            Frame::Command { .. } | Frame::Subnegotiation(_) => {
                let mut out = core::mem::take(&mut self.out);
                let result = self.negotiator.handle(frame, &mut out);
                self.out = out;
                if let Some(event) = result {
                    self.on_negotiated(event);
                }
            }
            Frame::Record(payload) => self.on_record(payload),
            Frame::Signal(_) => {}
        }
    }

    fn on_negotiated(&mut self, event: Negotiated) {
        match event {
            Negotiated::Ready {
                mode,
                device_type,
                lu,
                functions,
            } => {
                self.connected = true;
                // Adopt the negotiated model, which may differ from the request.
                if device_type.model != self.screen.model() {
                    self.screen = Screen::new(device_type.model);
                    self.screen.set_code_page(self.config.code_page);
                }
                self.events.push_back(Event::Connected {
                    mode,
                    device_type,
                    lu,
                    functions,
                });
            }
            Negotiated::DeviceRejected(reason) => {
                self.events.push_back(Event::DeviceRejected(reason))
            }
            Negotiated::Tn3270eDeclined => {}
        }
    }

    fn on_record(&mut self, payload: &[u8]) {
        if self.negotiator.mode() != Mode::Tn3270e {
            // Basic TN3270: the record is the data stream, no header.
            self.apply(payload, None);
            return;
        }

        let Some((header, body)) = Header::decode(payload) else {
            self.events.push_back(Event::ProtocolError(format!(
                "TN3270E record shorter than its 5-byte header: {} bytes",
                payload.len()
            )));
            return;
        };

        match header.data_type {
            DataType::Data3270 => self.apply(body, Some(header)),
            DataType::BindImage => self.on_bind_image(body),
            DataType::Unbind => {
                self.keyboard_locked = true;
                self.events.push_back(Event::Unbind);
            }
            DataType::SscpLu => {
                let text = self.screen.decode(body).trim_end().to_string();
                if !text.is_empty() {
                    self.events.push_back(Event::SscpText(text));
                }
            }
            DataType::Nvt => {
                let text = String::from_utf8_lossy(body).trim().to_string();
                if !text.is_empty() {
                    self.events.push_back(Event::NvtText(text));
                }
            }
            DataType::Response => {}
            other => self.events.push_back(Event::ProtocolError(format!(
                "unhandled TN3270E data type {other:?}"
            ))),
        }
    }

    fn on_bind_image(&mut self, body: &[u8]) {
        if !self.config.honour_bind_image {
            return;
        }
        let Some(bind) = parse_bind(body) else {
            self.events.push_back(Event::ProtocolError(
                "malformed BIND image, geometry left unchanged".into(),
            ));
            return;
        };
        // A descriptor of 0x03 means "the terminal's own maximum", reported
        // here as zeroes; keep the negotiated model size in that case.
        if bind.alternate_rows == 0 || bind.alternate_cols == 0 {
            return;
        }
        let (rows, cols) = (bind.alternate_rows, bind.alternate_cols);
        if (rows, cols) != (self.screen.rows(), self.screen.cols()) {
            self.screen.resize(rows, cols);
            self.events.push_back(Event::Resized { rows, cols });
        }
    }

    fn apply(&mut self, data: &[u8], header: Option<Header>) {
        match ds::apply(&mut self.screen, data) {
            Ok(parsed) => {
                if !parsed.structured_fields.is_empty() {
                    self.on_structured_fields(&parsed.structured_fields.clone());
                }
                if parsed.command.is_read() {
                    self.reply_to_read(parsed.command);
                }
                if self.screen.alarm {
                    self.screen.alarm = false;
                    self.events.push_back(Event::Alarm);
                }
                if parsed.command.has_wcc() || !parsed.structured_fields.is_empty() {
                    self.events.push_back(Event::ScreenUpdated);
                }
                if parsed.unlocks_keyboard() {
                    self.keyboard_locked = false;
                    self.events.push_back(Event::KeyboardUnlocked);
                }
                // A host that demands a response will wait forever without one.
                if let Some(h) = header {
                    if h.response_flag == ALWAYS_RESPONSE
                        && self.negotiator.has_function(Function::Responses)
                    {
                        self.send_positive_response(h.seq);
                    }
                }
            }
            Err(e) => {
                self.events
                    .push_back(Event::ProtocolError(describe_parse_error(&e)));
            }
        }
    }

    fn on_structured_fields(&mut self, fields: &[Vec<u8>]) {
        for field in fields {
            if self.config.auto_query_reply && sf::is_read_partition_query(field) {
                let dt = self.negotiator.device_type();
                let reply = sf::build_query_reply(dt.model, dt.color);
                self.send_data(&reply);
            }
        }
    }

    fn reply_to_read(&mut self, command: Command) {
        let record = match command {
            Command::ReadBuffer => ds::read_buffer(&self.screen),
            Command::ReadModified => ds::read_modified(&self.screen, Aid::None, false),
            Command::ReadModifiedAll => ds::read_modified(&self.screen, Aid::None, true),
            _ => return,
        };
        self.send_data(&record);
    }

    // --------------------------------------------------------------- send --

    /// Wrap a data stream payload and queue it, adding a TN3270E header when
    /// the session negotiated one.
    fn send_data(&mut self, payload: &[u8]) {
        let mut record = Vec::with_capacity(payload.len() + Header::LEN);
        if self.negotiator.mode() == Mode::Tn3270e {
            self.seq = self.seq.wrapping_add(1);
            record.extend_from_slice(&Header::new(DataType::Data3270, self.seq).encode());
        }
        record.extend_from_slice(payload);
        telnet::record_into(&record, &mut self.out);
    }

    fn send_positive_response(&mut self, seq: u16) {
        let header = Header {
            data_type: DataType::Response,
            request_flag: 0,
            response_flag: 0, // positive
            seq,
        };
        let mut record = header.encode().to_vec();
        record.push(POS_DEVICE_END);
        telnet::record_into(&record, &mut self.out);
    }

    // ------------------------------------------------------------ actions --

    /// Send an AID, handing control to the host.
    ///
    /// Locks the keyboard until the host unlocks it, which is what
    /// [`Event::KeyboardUnlocked`] reports.
    pub fn press(&mut self, aid: Aid) -> Result<(), ActionError> {
        if !self.connected {
            return Err(ActionError::NotConnected);
        }
        if self.keyboard_locked {
            return Err(ActionError::KeyboardLocked);
        }
        if aid.as_byte().is_none() {
            return Err(ActionError::InvalidKey);
        }
        let record = ds::read_modified(&self.screen, aid, false);
        self.send_data(&record);
        self.keyboard_locked = true;
        // CLEAR erases the screen locally, before the host answers.
        if aid.clears_screen() {
            self.screen.clear();
            self.events.push_back(Event::ScreenUpdated);
        }
        Ok(())
    }

    /// Move the cursor to a 1-based row and column.
    pub fn set_cursor(&mut self, row: u16, col: u16) {
        let addr = self.screen.addr_of(row, col);
        self.screen.set_cursor(addr);
    }

    /// Type text at the cursor, as an operator would.
    ///
    /// Advances the cursor, sets the modified-data-tag on each field touched,
    /// and refuses to write into a protected field. This is deliberately the
    /// simple case: insert mode, auto-skip and field overflow are not yet
    /// implemented.
    pub fn type_text(&mut self, text: &str) -> Result<(), ActionError> {
        if self.keyboard_locked {
            return Err(ActionError::KeyboardLocked);
        }
        let code_page = self.screen.code_page();
        for ch in text.chars() {
            let addr = self.screen.cursor();
            if !self.screen.is_writable(addr) {
                return Err(ActionError::ProtectedField {
                    row: self.screen.row_col(addr).0,
                    col: self.screen.row_col(addr).1,
                });
            }
            let attr = self.screen.field_attr(addr);
            if attr.map(|a| a.is_numeric()).unwrap_or(false)
                && !(ch.is_ascii_digit() || matches!(ch, '-' | '.' | ','))
            {
                return Err(ActionError::NotNumeric { ch });
            }
            let byte = code_page
                .encode_char(ch)
                .ok_or(ActionError::Unrepresentable { ch })?;
            self.screen.cell_mut(addr).byte = byte;
            self.screen.set_modified(addr, true);
            let next = self.screen.inc(addr);
            self.screen.set_cursor(next);
        }
        Ok(())
    }

    /// Move the cursor to the first data position of the next unprotected field.
    pub fn tab(&mut self) {
        let size = self.screen.size();
        let start = self.screen.cursor();
        let mut addr = self.screen.inc(start);
        for _ in 0..size {
            if self.screen.cell(addr).is_field_start() {
                let next = self.screen.inc(addr);
                if self.screen.is_writable(next) {
                    self.screen.set_cursor(next);
                    return;
                }
            }
            addr = self.screen.inc(addr);
        }
    }

    /// Fill the field at the cursor and press Enter, the common automation step.
    pub fn type_and_enter(&mut self, text: &str) -> Result<(), ActionError> {
        self.type_text(text)?;
        self.press(Aid::Enter)
    }
}

fn describe_parse_error(e: &ParseError) -> String {
    match e {
        ParseError::AddressOutOfRange { addr, max } => format!(
            "host addressed cell {addr} but the screen holds {}; \
             it is probably writing for the alternate size while the terminal \
             is on the primary one",
            max + 1
        ),
        other => other.to_string(),
    }
}

/// Why an action could not be performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionError {
    /// Negotiation has not finished.
    NotConnected,
    /// The host holds the keyboard; wait for [`Event::KeyboardUnlocked`].
    KeyboardLocked,
    /// The cursor is in a protected field.
    ProtectedField { row: u16, col: u16 },
    /// A numeric-only field rejected this character.
    NotNumeric { ch: char },
    /// The code page cannot represent this character.
    Unrepresentable { ch: char },
    /// A `Pf`/`Pa` number outside the valid range.
    InvalidKey,
}

impl core::fmt::Display for ActionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ActionError::NotConnected => f.write_str("negotiation has not finished"),
            ActionError::KeyboardLocked => {
                f.write_str("the host has the keyboard locked; wait for it to unlock")
            }
            ActionError::ProtectedField { row, col } => {
                write!(f, "position ({row},{col}) is in a protected field")
            }
            ActionError::NotNumeric { ch } => {
                write!(f, "a numeric-only field rejected {ch:?}")
            }
            ActionError::Unrepresentable { ch } => {
                write!(f, "the code page cannot represent {ch:?}")
            }
            ActionError::InvalidKey => f.write_str("no such PF or PA key"),
        }
    }
}

impl std::error::Error for ActionError {}
