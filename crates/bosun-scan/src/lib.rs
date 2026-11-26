//! The passive scanner.
//!
//! The recorder writes flows to the project; the scanner reads the ones it has not seen (a mark on each flow is
//! the queue, so the backlog of an old project, an import and a restart are all the same case), runs the
//! [`rules`] on them in small batches on its own thread and stores the findings. Nothing here sits on the proxy's
//! path: the proxy never waits for it, and it pauses between batches so the database writer stays free for the
//! recorder.

mod head;
pub mod rules;
mod scanner;

pub use rules::{RULES, scan_flow};
pub use scanner::Scanner;
