//! `hashcrack-rs`: the Rust Hash Cracker CLI — the parity twin of the Python
//! `hashcrack` command line (see specs/003-rust-backend/contracts/cli.md).

mod cmd_audit;
mod cmd_benchmark;
mod cmd_history;

// allow cmd_audit to reuse the passphrase chain
mod output;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use cmd_audit::{AuditRequest, Mode};

/// Arguments for the `audit` subcommand (boxed to keep the enum lean).
#[derive(clap::Args)]
struct AuditArgs {
    /// Target hash (omit when --hashlist is given).
    hash: Option<String>,
    /// Path to a hashlist file (one `algorithm:hash` or bare hash per line).
    #[arg(long)]
    hashlist: Option<PathBuf>,
    /// Mutation preset (dictionary mode only).
    #[arg(long, default_value = "none")]
    rules: String,
    /// Explicit algorithm choice (required for ambiguous shapes).
    #[arg(long)]
    algorithm: Option<String>,
    /// Audit mode.
    #[arg(long, value_enum)]
    mode: Mode,
    /// Wordlist file (dictionary mode).
    #[arg(long)]
    wordlist: Option<PathBuf>,
    /// Salt for salted formats.
    #[arg(long)]
    salt: Option<String>,
    /// Character set (brute-force mode).
    #[arg(long)]
    charset: Option<String>,
    /// Minimum candidate length (brute-force mode).
    #[arg(long)]
    min_length: Option<u64>,
    /// Maximum candidate length (brute-force mode).
    #[arg(long)]
    max_length: Option<u64>,
    /// Candidate budget (default 1,000,000; hard max 10,000,000).
    #[arg(long, default_value_t = 1_000_000)]
    max_candidates: u64,
    /// Worker threads (1-8, default 4).
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Store the recovered plaintext encrypted (passphrase prompt).
    #[arg(long)]
    encrypt: bool,
    /// Passphrase for --encrypt.
    #[arg(long)]
    passphrase: Option<String>,
    /// Withhold the plaintext from local history.
    #[arg(long)]
    no_store_plaintext: bool,
    /// Acknowledge the retention warning automatically.
    #[arg(long)]
    yes: bool,
    /// History database path.
    #[arg(long)]
    database: Option<PathBuf>,
}

#[derive(Parser)]
#[command(
    name = "hashcrack-rs",
    version,
    about = "Offline password audit tool (Rust backend)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Assess a hash shape.
    Identify {
        /// The submitted hash value.
        hash: String,
    },
    /// Run an audit (dictionary or brute-force) against a target.
    Audit(Box<AuditArgs>),
    /// Print per-algorithm throughput.
    Benchmark {
        /// Wall-clock seconds per algorithm.
        #[arg(long, default_value_t = 2.0)]
        seconds: f64,
        /// Comma-separated algorithm list (default: all unsalted formats).
        #[arg(long)]
        algorithms: Option<String>,
    },
    /// Show local audit history.
    History {
        /// Maximum records to show.
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Passphrase for unlocking encrypted plaintext.
        #[arg(long)]
        passphrase: Option<String>,
        /// Unlock encrypted plaintext before listing.
        #[arg(long)]
        unlock: bool,
        /// History database path.
        #[arg(long)]
        database: Option<PathBuf>,
    },
    /// Export audit history to a file.
    Export {
        /// Output file path.
        path: PathBuf,
        /// Export format.
        #[arg(long, default_value = "csv")]
        format: String,
        /// History database path.
        #[arg(long)]
        database: Option<PathBuf>,
    },
    /// Start the local web dashboard (Rust backend).
    Serve {
        /// TCP port to bind on 127.0.0.1.
        #[arg(long, default_value_t = 8765)]
        port: u16,
        /// Static frontend directory.
        #[arg(long)]
        static_dir: Option<PathBuf>,
        /// History database path.
        #[arg(long)]
        database: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Identify { hash } => cmd_identify(&hash),
        Commands::Audit(args) => {
            let AuditArgs {
                hash,
                hashlist,
                rules,
                algorithm,
                mode,
                wordlist,
                salt,
                charset,
                min_length,
                max_length,
                max_candidates,
                workers,
                encrypt,
                passphrase,
                no_store_plaintext,
                yes,
                database,
            } = *args;
            if passphrase.is_some() && !encrypt {
                eprintln!("--passphrase requires --encrypt.");
                std::process::exit(cmd_audit::EXIT_INVALID);
            }
            let request = AuditRequest {
                hash,
                hashlist,
                rules,
                algorithm,
                mode,
                wordlist,
                salt,
                charset,
                min_length,
                max_length,
                max_candidates,
                workers,
                no_store_plaintext,
                yes,
                encrypt,
                passphrase,
                database: database.unwrap_or_else(hc_history::default_db_path),
            };
            cmd_audit::run(request)
        }
        Commands::Benchmark { seconds, algorithms } => {
            cmd_benchmark::run(cmd_benchmark::BenchmarkRequest {
                seconds,
                algorithms,
            })
        }
        Commands::History {
            limit,
            passphrase,
            unlock,
            database,
        } => cmd_history::run_history(cmd_history::HistoryRequest {
            limit,
            passphrase,
            unlock,
            database: database.unwrap_or_else(hc_history::default_db_path),
        }),
        Commands::Export {
            path,
            format,
            database,
        } => cmd_history::run_export(cmd_history::ExportRequest {
            path,
            format,
            database: database.unwrap_or_else(hc_history::default_db_path),
        }),
        Commands::Serve {
            port,
            static_dir,
            database,
        } => cmd_serve(port, static_dir, database),
    };
    std::process::exit(code);
}

/// Shared serve path: same router as the hc-server binary, loopback-only.
fn cmd_serve(port: u16, static_dir: Option<PathBuf>, database: Option<PathBuf>) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("Cannot start async runtime: {err}");
            return cmd_audit::EXIT_STORAGE;
        }
    };
    runtime.block_on(async move {
        let db_path = database.unwrap_or_else(hc_history::default_db_path);
        let store = match hc_history::Store::open(&db_path) {
            Ok(store) => store,
            Err(err) => {
                eprintln!("Cannot open local history database: {err}");
                return cmd_audit::EXIT_STORAGE;
            }
        };
        let state = std::sync::Arc::new(hc_server::app::AppState {
            static_dir: static_dir.unwrap_or_else(hc_server::static_files::default_static_dir),
            store,
            jobs: hc_server::jobs::JobRegistry::new(db_path.clone()),
        });
        hc_server::jobs::restore_paused_jobs(&state);
        let router = hc_server::app::build_router(state);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("Cannot bind 127.0.0.1:{port}: {err}");
                return cmd_audit::EXIT_STORAGE;
            }
        };
        println!("Serving the Hash Cracker dashboard (Rust backend) on http://{addr}");
        match axum::serve(listener, router).await {
            Ok(()) => cmd_audit::EXIT_OK,
            Err(err) => {
                eprintln!("Server error: {err}");
                cmd_audit::EXIT_STORAGE
            }
        }
    })
}

fn cmd_identify(hash: &str) -> i32 {
    use hc_core::identify::assess_hash;
    match assess_hash(hash) {
        Err(err) => {
            eprintln!("Invalid hash input: {err}");
            cmd_audit::EXIT_INVALID
        }
        Ok(assessment) => {
            println!(
                "Hash shape: {} hexadecimal characters.",
                assessment.normalized.len()
            );
            if assessment.ambiguous {
                let names: Vec<String> = assessment
                    .compatible_algorithms
                    .iter()
                    .map(|a| a.to_uppercase())
                    .collect();
                let choices: Vec<String> = assessment
                    .compatible_algorithms
                    .iter()
                    .map(|a| format!("--algorithm {a}"))
                    .collect();
                println!("Compatible supported formats: {}", names.join(", "));
                println!(
                    "This shape is ambiguous: several supported formats share it, so
the algorithm cannot be proven from structure alone. Select one
explicitly when running an audit ({}).",
                    choices.join(" or ")
                );
            } else {
                let algorithm = assessment.compatible_algorithms[0];
                println!("Compatible supported format: {}", algorithm.to_uppercase());
            }
            cmd_audit::EXIT_OK
        }
    }
}
