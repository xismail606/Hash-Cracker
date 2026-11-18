//! `hc-server`: the Hash Cracker local dashboard server (Rust backend) —
//! REST contract twin of the Flask app; loopback-only.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hc_server::{app, jobs, static_files};

#[derive(clap::Parser)]
#[command(name = "hc-server", version, about = "Hash Cracker dashboard server (Rust)")]
struct Args {
    /// TCP port to bind on 127.0.0.1.
    #[arg(long, default_value_t = 8765)]
    port: u16,
    /// Static frontend directory (default: src/hash_cracker/static).
    #[arg(long)]
    static_dir: Option<PathBuf>,
    /// History database path.
    #[arg(long)]
    database: Option<PathBuf>,
}

fn main() {
    let args = <Args as clap::Parser>::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async_main(args));
}

async fn async_main(args: Args) {
    let db_path = args.database.unwrap_or_else(hc_history::default_db_path);
    let store = match hc_history::Store::open(&db_path) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("Cannot open local history database: {err}");
            std::process::exit(3);
        }
    };
    let state = Arc::new(app::AppState {
        static_dir: args.static_dir.unwrap_or_else(static_files::default_static_dir),
        store,
        jobs: jobs::JobRegistry::new(db_path.clone()),
    });
    // Restart recovery: restore the newest paused job, clean stale records.
    jobs::restore_paused_jobs(&state);

    let router = app::build_router(Arc::clone(&state));
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|err| {
            eprintln!("Cannot bind 127.0.0.1:{}: {err}", args.port);
            std::process::exit(1);
        });
    println!(
        "Serving the Hash Cracker dashboard (Rust backend) on http://{addr}"
    );
    if let Err(err) = axum::serve(listener, router).await {
        eprintln!("Server error: {err}");
        std::process::exit(1);
    }
}
