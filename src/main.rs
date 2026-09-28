//! `netor` — a system-level network traffic monitor.
//!
//! Each subcommand lives in its own module: `cli` parses arguments, `iface`
//! samples interface counters, `live` reads the OS connection table, `capture`
//! owns the platform capture backends, and `proto` dissects packets.

mod capture;
mod cli;
mod filter;
mod format;
mod iface;
mod live;
mod proto;
mod shutdown;
mod tally;

use crate::capture::{capture_web_events, print_web_events, Capture};
use crate::cli::{Cli, Command, LiveArgs, NetworkArgs, WebArgs};
use crate::format::trim_float;
use crate::iface::{collect_interface_rows, print_interface_rows};
use crate::live::{collect_live_connections, print_live_connections};
use crate::shutdown::{install_ctrlc_handler, wait_for_interval};
use clap::Parser;
use std::error::Error;
use std::time::{Duration, Instant};
use sysinfo::Networks;

fn main() {
    restore_default_sigpipe();
    if let Err(error) = run() {
        eprintln!("netor: {error}");
        std::process::exit(1);
    }
}

/// Restores the default `SIGPIPE` disposition.
///
/// Rust ignores `SIGPIPE`, so a closed stdout makes `println!` fail and the
/// process aborts with a "failed printing to stdout" panic. Since every
/// subcommand streams output until interrupted, piping into `head` is a
/// natural thing to do and should end the process quietly, as with any other
/// Unix filter, instead of printing a panic.
#[cfg(unix)]
fn restore_default_sigpipe() {
    // SAFETY: setting a process-wide signal disposition to its default is
    // async-signal-safe and happens before any other thread is started.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_sigpipe() {}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Live(args)) => run_live(args),
        Some(Command::Web(args)) => run_web(args),
        None => run_network(cli.network),
    }
}

fn run_network(cli: NetworkArgs) -> Result<(), Box<dyn Error>> {
    let interval = Duration::from_secs_f64(cli.interval);
    let running = install_ctrlc_handler()?;

    let mut networks = Networks::new_with_refreshed_list();
    if networks.is_empty() {
        return Err("no network interfaces found".into());
    }

    println!(
        "netor: interface traffic, interval={}s, filter={}",
        trim_float(cli.interval),
        cli.interface.as_deref().unwrap_or("*")
    );

    let mut sampled_at = Instant::now();
    loop {
        if !wait_for_interval(interval, &running) {
            break;
        }
        networks.refresh(true);
        let now = Instant::now();
        let elapsed_secs = now.duration_since(sampled_at).as_secs_f64();
        sampled_at = now;

        let rows = collect_interface_rows(&networks, &cli, elapsed_secs);
        print_interface_rows(&rows, cli.unit);

        if cli.once || !running.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
    }

    Ok(())
}

fn run_live(cli: LiveArgs) -> Result<(), Box<dyn Error>> {
    let interval = Duration::from_secs_f64(cli.interval);
    let running = install_ctrlc_handler()?;

    println!(
        "netor live: interval={}s, states={}",
        trim_float(cli.interval),
        if cli.all_states { "all" } else { "established" }
    );
    println!("note: this uses OS TCP connection tables; HTTPS/CDN traffic may only show IP:port");

    loop {
        let connections = collect_live_connections(cli.all_states)?;
        print_live_connections(&connections, cli.top);

        if cli.once || !running.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        if !wait_for_interval(interval, &running) {
            break;
        }
    }

    Ok(())
}

fn run_web(cli: WebArgs) -> Result<(), Box<dyn Error>> {
    let interval = Duration::from_secs_f64(cli.interval);
    let running = install_ctrlc_handler()?;

    println!(
        "netor web: protocol capture, interval={}s, interface={}",
        trim_float(cli.interval),
        cli.interface.as_deref().unwrap_or("*")
    );
    println!(
        "note: captures DNS queries and TLS SNI from packets; root/CAP_NET_RAW is usually required"
    );

    // The handle is opened once and reused, so no traffic is lost between
    // windows the way it was when a raw socket was recreated each time.
    let mut capture = Capture::open(cli.interface.as_deref())?;

    loop {
        let events = capture_web_events(&mut capture, interval, &running)?;
        print_web_events(&events, cli.top);

        if cli.once || !running.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
    }

    Ok(())
}
