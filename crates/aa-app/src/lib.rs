//! What a program built around the engine needs besides the engine: writing a report in every
//! output format ([`export`]), keeping finished reports ([`history`]), and running an analysis
//! in a worker process that can be cancelled for certain ([`run`]).
//!
//! The command line and the desktop app both write their files through [`export`], which is how
//! the two give the same bytes for the same report. Nothing here draws a window; the desktop app
//! is a thin layer of commands over this crate.

pub mod export;
pub mod history;
pub mod run;
