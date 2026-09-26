//! An IBM 3270 terminal emulator and automation library, with no C dependencies.
//!
//! # Design
//!
//! The protocol core is **sans-IO**: it never touches a socket. A [`Session`]
//! is fed inbound bytes, and produces outbound bytes plus a queue of
//! [`Event`]s. That has three consequences worth knowing:
//!
//! * unit tests need no network, so a recorded byte stream is a complete
//!   fixture;
//! * the same core drives blocking, async or in-process transports;
//! * the protocol logic can be compared against a reference implementation by
//!   feeding both the identical stream.
//!
//! A blocking TCP transport is provided behind the `tcp` feature, which is on
//! by default.
//!
//! # Layers
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`ebcdic`] | EBCDIC code page conversion |
//! | [`telnet`] | telnet framing: IAC escaping, records, subnegotiation |
//! | [`negotiate`] | TN3270E (RFC 2355) and basic TN3270 (RFC 1576) negotiation |
//! | [`ds`] | the 3270 data stream: orders, attributes, addressing |
//! | [`screen`] | the screen buffer, fields and cursor |
//! | [`session`] | the sans-IO session that ties them together |

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod ds;
pub mod ebcdic;
pub mod negotiate;
pub mod screen;
pub mod session;
pub mod telnet;

#[cfg(feature = "tcp")]
pub mod transport;

pub use ds::FieldAttr;
pub use ds::{Aid, Command, Order};
pub use ebcdic::CodePage;
pub use negotiate::{DeviceType, Function, Mode};
pub use screen::{Cell, Field, Model, Screen};
pub use session::{ActionError, Event, Session, SessionConfig};

#[cfg(feature = "tcp")]
pub use transport::{Connection, WaitError};
