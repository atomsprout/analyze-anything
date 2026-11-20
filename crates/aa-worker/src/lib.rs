//! Runs an analysis in a process of its own, so that whoever asked for it can end it for certain.
//!
//! A thread that is stuck cannot be stopped; a process can. The desktop app therefore starts a
//! worker process for every analysis and talks to it over its standard input and output:
//!
//! * [`protocol`] is what the two sides say to each other: one JSON object per line.
//! * [`serve`] is the worker's side: it reads requests, runs the engine, and writes responses.
//! * [`Worker`] is the other side: it starts the process, sends requests, hands back responses,
//!   and ends the process, by asking first and by force if it does not answer.
//!
//! The worker is the same program started with a hidden argument, so nothing extra is shipped.
//! A worker reads the input and writes only inside the scratch folder it is given; whoever
//! started it removes that folder afterwards, whatever happened to the worker.

mod client;
pub mod protocol;
mod server;

pub use client::{Worker, WorkerError};
pub use server::{serve, serve_with_registry};
