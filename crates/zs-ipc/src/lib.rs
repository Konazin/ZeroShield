//! ZeroShield IPC.
//!
//! The daemon (`zeroshieldd`) listens on a unix socket and speaks
//! newline-delimited JSON. Two frame shapes exist:
//!
//! * requests:  `{"id":1,"method":"scan.run","params":{...}}`
//! * responses: `{"id":1,"ok":true,"result":{...}}`
//! * events:    `{"event":{"type":"scan_progress",...}}` (broadcast/streamed)
//!
//! Long running calls (e.g. `scan.run`) stream `event` frames before the final
//! `response` frame with the same id.

pub mod client;
pub mod protocol;
pub mod server;

pub use client::Client;
pub use protocol::{methods, EventEnvelope, Frame, PeerCred, Request, Response};
pub use server::{FrameTx, Handler, HandlerFuture, Server};
