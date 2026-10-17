//! `zeroshield` — ZeroShield command line interface.

mod commands;
mod local;
mod render;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use commands::{Ctx, MetricsArgs, ReportArgs, ScanArgs};
use zs_core::error::ZsResult;

#[derive(Parser, Debug)]
#[command(
    name = "zeroshield",
    version,
    about = "ZeroShield — open source antivirus and IPS for Linux"
)]
struct Cli {
    /// Configuration file
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// JSON output
    #[arg(long, global = true)]
    json: bool,

    /// Disable colors
    #[arg(long, global = true)]
    no_color: bool,

    /// Run everything in this process (do not talk to the daemon)
    #[arg(long, global = true)]
    local: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show daemon/engine status
    Status,

    /// Scan files and directories
    Scan(ScanCmd),

    /// Process monitor
    Proc(ProcCmd),

    /// Real-time file watching (daemon sessions)
    Watch(WatchCmd),

    /// Quarantine management
    Quarantine(QuarantineCmd),

    /// Content rules and hash signatures
    Rules(RulesCmd),

    /// Network guard (IPS)
    Net(NetCmd),

    /// Recent events
    Events {
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: u32,
        /// Keep the connection open and stream events (requires the daemon)
        #[arg(short = 'f', long)]
        follow: bool,
    },

    /// Recent findings
    Findings {
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: u32,
    },

    /// Build a report (JSON, CSV or self-contained HTML)
    Report(ReportCmd),

    /// Export metrics (Prometheus text or journald lines)
    Metrics(MetricsCmd),

    /// Terminal user interface (requires the daemon)
    Tui,

    /// List engine modules
    Modules,

    /// Interactive shell
    Shell,
}

#[derive(Args, Debug)]
struct ScanCmd {
    /// Files or directories to scan
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Do not descend into directories
    #[arg(long)]
    no_recursive: bool,

    /// Quarantine malicious files
    #[arg(short = 'q', long)]
    quarantine: bool,

    /// Minimum score to report (0-100)
    #[arg(long, value_name = "N")]
    min_score: Option<u32>,

    /// Skip files larger than this many bytes
    #[arg(long, value_name = "BYTES")]
    max_size: Option<u64>,

    /// Follow symbolic links
    #[arg(long)]
    follow_symlinks: bool,
}

#[derive(Args, Debug)]
struct ProcCmd {
    #[command(subcommand)]
    action: Option<ProcAction>,
}

#[derive(Subcommand, Debug)]
enum ProcAction {
    /// List processes ordered by suspicion score
    List {
        #[arg(long, default_value_t = 0)]
        min_score: u32,
    },
    /// Full audit (same as list with --min-score 0)
    Audit {
        #[arg(long, default_value_t = 0)]
        min_score: u32,
    },
    /// Watch for new suspicious processes
    Watch,
}

#[derive(Args, Debug)]
struct ReportCmd {
    /// Output format
    #[arg(long, value_parser = ["json", "csv", "html"], default_value = "json")]
    format: String,

    /// Include records from the last N days (0 = all time)
    #[arg(long, default_value_t = 7)]
    days: u32,

    /// Maximum rows per section
    #[arg(long, default_value_t = 1000)]
    limit: u32,

    /// CSV only: table to export (findings, scans, events, quarantine)
    #[arg(long, value_name = "TABLE")]
    section: Option<String>,

    /// Write to FILE instead of stdout
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct MetricsCmd {
    /// Output format
    #[arg(
        long,
        value_parser = ["prometheus", "journald"],
        default_value = "prometheus"
    )]
    format: String,

    /// Write to FILE instead of stdout
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct WatchCmd {
    /// Directories to watch (defaults to watch.paths from the configuration)
    paths: Vec<PathBuf>,

    /// Quarantine malicious files immediately
    #[arg(short = 'q', long)]
    quarantine: bool,

    /// Do not watch subdirectories
    #[arg(long)]
    no_recursive: bool,

    /// Start the session in the daemon and exit
    #[arg(long)]
    detach: bool,

    /// List active watch sessions and exit
    #[arg(long)]
    list: bool,

    /// Stop sessions: all, or only those covering the given paths
    #[arg(long)]
    stop: bool,
}

#[derive(Args, Debug)]
struct QuarantineCmd {
    #[command(subcommand)]
    action: QuarantineAction,
}

#[derive(Subcommand, Debug)]
enum QuarantineAction {
    /// List quarantined files
    List,
    /// Restore a quarantined file
    Restore {
        /// Quarantine entry id
        id: i64,
    },
    /// Delete a quarantined file permanently
    Purge {
        /// Quarantine entry id
        id: i64,
    },
}

#[derive(Args, Debug)]
struct RulesCmd {
    #[command(subcommand)]
    action: RulesAction,
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    /// List loaded content rules
    List,
    /// Explain detections for one file (rules + heuristics + signatures)
    Check {
        /// File to check
        file: PathBuf,
    },
    /// Import hash signatures (ClamAV .hdb, ZeroShield CSV or plain lists)
    Import {
        /// Signature file
        file: PathBuf,
        /// auto | clam | csv | plain
        #[arg(long, default_value = "auto")]
        format: String,
    },
}

#[derive(Args, Debug)]
struct NetCmd {
    #[command(subcommand)]
    action: NetAction,
}

#[derive(Subcommand, Debug)]
enum NetAction {
    /// Show netguard status
    Status,
    /// Explain what would happen to these targets (IP/CIDR/domain/URL)
    Audit { targets: Vec<String> },
    /// Threat feed management
    Feeds {
        #[command(subcommand)]
        action: FeedsAction,
    },
    /// Generate (and with --yes, install) the nftables ruleset
    Apply {
        /// Really apply the ruleset (requires root + block mode)
        #[arg(long)]
        yes: bool,
    },
    /// Write the DNS sinkhole fragment
    Dns {
        /// Install it into the resolver include directory (requires root)
        #[arg(long)]
        install: bool,
    },
}

#[derive(Subcommand, Debug)]
enum FeedsAction {
    /// Download and ingest all configured feeds
    Update {
        /// Ignore the cache TTL
        #[arg(long)]
        force: bool,
    },
    /// Show stored indicators grouped by source
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("zeroshield: failed to start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli)) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("zeroshield: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> ZsResult<i32> {
    let ctx = Ctx::load(cli.config.clone(), cli.json, cli.local, cli.no_color)?;
    run_command(&ctx, cli).await
}

async fn run_command(ctx: &Ctx, cli: Cli) -> ZsResult<i32> {
    match cli.command {
        None | Some(Command::Status) => {
            commands::cmd_status(ctx).await?;
            Ok(0)
        }
        Some(Command::Scan(cmd)) => {
            let threats = commands::cmd_scan(
                ctx,
                &cmd.paths,
                ScanArgs {
                    recursive: !cmd.no_recursive,
                    quarantine: cmd.quarantine,
                    min_score: cmd.min_score,
                    max_size: cmd.max_size,
                    follow_symlinks: cmd.follow_symlinks,
                },
            )
            .await?;
            // exit code 2 mirrors "grep-like" tooling: threats were found.
            Ok(if threats { 2 } else { 0 })
        }
        Some(Command::Proc(cmd)) => {
            match cmd.action {
                Some(ProcAction::List { min_score }) | Some(ProcAction::Audit { min_score }) => {
                    commands::cmd_proc_list(ctx, min_score).await?;
                }
                Some(ProcAction::Watch) => commands::cmd_proc_watch(ctx).await?,
                None => commands::cmd_proc_list(ctx, 0).await?,
            }
            Ok(0)
        }
        Some(Command::Watch(cmd)) => {
            commands::cmd_watch(
                ctx,
                commands::WatchArgs {
                    paths: cmd.paths,
                    quarantine: cmd.quarantine,
                    recursive: !cmd.no_recursive,
                    detach: cmd.detach,
                    list: cmd.list,
                    stop: cmd.stop,
                },
            )
            .await?;
            Ok(0)
        }
        Some(Command::Quarantine(cmd)) => {
            match cmd.action {
                QuarantineAction::List => commands::cmd_quarantine_list(ctx).await?,
                QuarantineAction::Restore { id } => {
                    commands::cmd_quarantine_restore(ctx, id).await?
                }
                QuarantineAction::Purge { id } => commands::cmd_quarantine_purge(ctx, id).await?,
            }
            Ok(0)
        }
        Some(Command::Rules(cmd)) => {
            match cmd.action {
                RulesAction::List => commands::cmd_rules_list(ctx).await?,
                RulesAction::Check { file } => commands::cmd_rules_check(ctx, &file).await?,
                RulesAction::Import { file, format } => {
                    commands::cmd_rules_import(ctx, &file, &format).await?
                }
            }
            Ok(0)
        }
        Some(Command::Net(cmd)) => {
            match cmd.action {
                NetAction::Status => commands::cmd_net_status(ctx).await?,
                NetAction::Audit { targets } => commands::cmd_net_audit(ctx, &targets).await?,
                NetAction::Feeds { action } => match action {
                    FeedsAction::Update { force } => {
                        commands::cmd_net_feeds_update(ctx, force).await?
                    }
                    FeedsAction::List => commands::cmd_net_feeds_list(ctx).await?,
                },
                NetAction::Apply { yes } => commands::cmd_net_apply(ctx, yes).await?,
                NetAction::Dns { install } => commands::cmd_net_dns(ctx, install).await?,
            }
            Ok(0)
        }
        Some(Command::Events { limit, follow }) => {
            commands::cmd_events(ctx, limit, follow).await?;
            Ok(0)
        }
        Some(Command::Findings { limit }) => {
            commands::cmd_findings(ctx, limit).await?;
            Ok(0)
        }
        Some(Command::Report(cmd)) => {
            commands::cmd_report(
                ctx,
                ReportArgs {
                    format: cmd.format,
                    days: cmd.days,
                    limit: cmd.limit,
                    section: cmd.section,
                    out: cmd.out,
                },
            )
            .await?;
            Ok(0)
        }
        Some(Command::Metrics(cmd)) => {
            commands::cmd_metrics(
                ctx,
                MetricsArgs {
                    format: cmd.format,
                    out: cmd.out,
                },
            )
            .await?;
            Ok(0)
        }
        Some(Command::Tui) => {
            zs_tui::run(ctx.paths.socket_path()).await?;
            Ok(0)
        }
        Some(Command::Modules) => {
            commands::cmd_modules(ctx).await?;
            Ok(0)
        }
        Some(Command::Shell) => {
            shell(ctx).await;
            Ok(0)
        }
    }
}

async fn shell(ctx: &Ctx) {
    use std::io::{BufRead, Write};

    println!(
        "ZeroShield {} interactive shell — type 'help' for commands, 'exit' to leave",
        zs_core::VERSION
    );
    let stdin = std::io::stdin();
    loop {
        print!("zeroshield> ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line {
            "exit" | "quit" => break,
            "help" => {
                println!(
                    "commands:\n  status\n  scan <path> [--quarantine] [--min-score N]\n  proc list [--min-score N]\n  proc watch\n  watch <dirs...> [-q] [--detach|--list|--stop]\n  quarantine list|restore <id>|purge <id>\n  rules list|check <file>|import <file>\n  net status|audit <targets...>|feeds update|feeds list|apply|dns\n  events [-n N] [--follow]\n  findings [-n N]\n  report [--format json|csv|html] [--days N] [--out FILE]\n  metrics [--format prometheus|journald] [--out FILE]\n  tui\n  modules\n  clear\n  exit"
                );
                continue;
            }
            "clear" => {
                print!("\x1b[2J\x1b[H");
                continue;
            }
            _ => {}
        }
        let mut argv: Vec<String> = vec!["zeroshield".to_string()];
        argv.extend(line.split_whitespace().map(String::from));
        let parsed = match Cli::try_parse_from(argv) {
            Ok(cli) => cli,
            Err(e) => {
                println!("{e}");
                continue;
            }
        };
        if matches!(parsed.command, Some(Command::Shell)) {
            continue;
        }
        if let Err(e) = Box::pin(run_command(ctx, parsed)).await {
            eprintln!("error: {e}");
        }
    }
}
