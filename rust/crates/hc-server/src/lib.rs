//! hc-server library surface: the REST contract twin of the Flask app.
//! Exposed for integration tests and the hc-cli `serve` subcommand.

pub mod app;
pub mod crypto;
pub mod jobs;
pub mod routes;
pub mod static_files;
