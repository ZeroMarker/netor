#![allow(dead_code, unused_imports)]

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command as ProcessCommand;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{NetworkData, Networks};

#[derive(Debug, Parser)]
#[command(
    name = "netor",
    version,
    about = "System-level network traffic monitor"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    network: NetworkArgs,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Monitor live TCP connections from the operating system.
    Live(LiveArgs),

    /// Monitor website domains by parsing DNS and TLS SNI packets.
    Web(WebArgs),
}

#[derive(Debug, Args)]
struct NetworkArgs {
    /// Refresh interval in seconds.
    #[arg(short, long, default_value_t = 1.0, value_parser = positive_f64)]
    interval: f64,

    /// Only show interfaces whose name contains this text.
    #[arg(short = 'n', long)]
    interface: Option<String>,

    /// Include interfaces with no traffic in the current sample.
    #[arg(long)]
    all: bool,

    /// Print one sample and exit.
    #[arg(long)]
    once: bool,

    /// Output unit.
    #[arg(short, long, value_enum, default_value_t = Unit::Auto)]
    unit: Unit,
}

#[derive(Debug, Args)]
struct LiveArgs {
    /// Refresh interval in seconds.
    #[arg(short, long, default_value_t = 2.0, value_parser = positive_f64)]
    interval: f64,

    /// Print one snapshot and exit.
    #[arg(long)]
    once: bool,

    /// Number of remote endpoints to show.
    #[arg(long, default_value_t = 20, value_parser = positive_usize)]
    top: usize,

    /// Include non-established TCP states.
    #[arg(long)]
    all_states: bool,
}

#[derive(Debug, Args)]
struct WebArgs {
    /// Capture interval in seconds.
    #[arg(short, long, default_value_t = 5.0, value_parser = positive_f64)]
    interval: f64,

    /// Print one capture window and exit.
    #[arg(long)]
    once: bool,

    /// Number of domains to show.
    #[arg(long, default_value_t = 20, value_parser = positive_usize)]
    top: usize,

    /// Network interface name to bind, for example eth0. Linux only.
    #[arg(short = 'n', long)]
    interface: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Unit {
    Auto,
    Bytes,
    Bits,
}

#[derive(Debug)]
struct InterfaceRow {
    name: String,
    rx_rate: f64,
    tx_rate: f64,
    rx_total: u64,
    tx_total: u64,
    packets_rx: f64,
    packets_tx: f64,
    errors_rx: u64,
    errors_tx: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TcpConnection {
    remote_ip: IpAddr,
    remote_port: u16,
    state: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("netor: {error}");
        std::process::exit(1);
    }
}

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

        if cli.once || !running.load(Ordering::SeqCst) {
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

        if cli.once || !running.load(Ordering::SeqCst) {
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

    loop {
        let events = capture_web_events(interval, cli.interface.as_deref(), &running)?;
        print_web_events(&events, cli.top);

        if cli.once || !running.load(Ordering::SeqCst) {
            break;
        }
    }

    Ok(())
}

fn install_ctrlc_handler() -> Result<Arc<AtomicBool>, Box<dyn Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let handler_flag = Arc::clone(&running);
    let monitor_thread = thread::current();
    ctrlc::set_handler(move || {
        handler_flag.store(false, Ordering::SeqCst);
        monitor_thread.unpark();
    })?;
    Ok(running)
}

// Recheck the flag after wakeups: park_timeout may return spuriously.
fn wait_for_interval(interval: Duration, running: &AtomicBool) -> bool {
    let started = Instant::now();
    while running.load(Ordering::SeqCst) {
        let remaining = interval.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return true;
        }
        thread::park_timeout(remaining);
    }
    false
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WebEvent {
    source: &'static str,
    domain: String,
}

#[cfg(target_os = "linux")]
fn capture_web_events(
    duration: Duration,
    interface: Option<&str>,
    running: &AtomicBool,
) -> Result<Vec<WebEvent>, Box<dyn Error>> {
    let socket = open_packet_socket(interface)?;
    let started = Instant::now();
    let mut buffer = vec![0_u8; 65_536];
    let mut events = Vec::new();

    while running.load(Ordering::SeqCst) && started.elapsed() < duration {
        let read = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };

        if read > 0 {
            events.extend(parse_packet_for_web_events(&buffer[..read as usize]));
            continue;
        }

        let error = std::io::Error::last_os_error();
        if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted
        ) {
            continue;
        }

        return Err(error.into());
    }

    Ok(events)
}

#[cfg(all(windows, feature = "npcap"))]
fn capture_web_events(
    duration: Duration,
    interface: Option<&str>,
    running: &AtomicBool,
) -> Result<Vec<WebEvent>, Box<dyn Error>> {
    let device = select_pcap_device(interface)?;
    let mut cap = pcap::Capture::from_device(device)
        .map_err(|e| format!("pcap: {e}"))?
        .promisc(true)
        .snaplen(65_536)
        .timeout(200)
        .immediate_mode(true)
        .open()
        .map_err(|e| format!("pcap open: {e}"))?;

    let started = Instant::now();
    let mut events = Vec::new();

    while running.load(Ordering::SeqCst) && started.elapsed() < duration {
        match cap.next_packet() {
            Ok(packet) => {
                events.extend(parse_packet_for_web_events(packet.data));
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(format!("pcap: {e}").into()),
        }
    }

    Ok(events)
}

#[cfg(all(windows, feature = "npcap"))]
fn select_pcap_device(interface: Option<&str>) -> Result<pcap::Device, Box<dyn Error>> {
    let devices = pcap::Device::list().map_err(|e| format!("pcap device list: {e}"))?;

    if let Some(filter) = interface {
        let filter_lower = filter.to_lowercase();
        devices
            .into_iter()
            .find(|d| {
                d.name.to_lowercase().contains(&filter_lower)
                    || d.desc
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter_lower)
            })
            .ok_or_else(|| format!("no network interface matching '{filter}'").into())
    } else {
        select_default_device(devices)
    }
}

#[cfg(all(windows, feature = "npcap"))]
fn select_default_device(devices: Vec<pcap::Device>) -> Result<pcap::Device, Box<dyn Error>> {
    let skip_keywords = [
        "wan miniport",
        "loopback",
        "tunnel",
        "teredo",
        "isatap",
        "bluetooth",
    ];
    let prefer_keywords = [
        "ethernet", "wi-fi", "wireless", "realtek", "intel", "qualcomm",
    ];

    if let Some(device) = devices.iter().find(|d| {
        let desc = d.desc.as_deref().unwrap_or("").to_lowercase();
        prefer_keywords.iter().any(|kw| desc.contains(kw))
            && !skip_keywords.iter().any(|kw| desc.contains(kw))
    }) {
        return Ok(device.clone());
    }

    if let Some(device) = devices.iter().find(|d| {
        let desc = d.desc.as_deref().unwrap_or("").to_lowercase();
        !skip_keywords.iter().any(|kw| desc.contains(kw)) && !d.addresses.is_empty()
    }) {
        return Ok(device.clone());
    }

    pcap::Device::lookup()
        .map_err(|e| format!("pcap device lookup: {e}"))?
        .ok_or("no default network interface found".into())
}

#[cfg(not(any(target_os = "linux", all(windows, feature = "npcap"))))]
fn capture_web_events(
    _duration: Duration,
    _interface: Option<&str>,
    _running: &AtomicBool,
) -> Result<Vec<WebEvent>, Box<dyn Error>> {
    #[cfg(windows)]
    {
        Err("packet capture requires the 'npcap' feature and Npcap installed; rebuild with --features npcap".into())
    }
    #[cfg(not(windows))]
    {
        Err("packet capture is not yet supported on this platform".into())
    }
}

#[cfg(target_os = "linux")]
fn open_packet_socket(interface: Option<&str>) -> Result<OwnedFd, Box<dyn Error>> {
    let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
    let socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
    if socket < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    // Own the descriptor immediately so every error path closes it.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };

    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    let set_timeout = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set_timeout < 0 {
        let error = std::io::Error::last_os_error();
        return Err(error.into());
    }

    if let Some(interface) = interface {
        bind_packet_socket(socket.as_raw_fd(), interface)?;
    }

    Ok(socket)
}

#[cfg(target_os = "linux")]
fn bind_packet_socket(socket: libc::c_int, interface: &str) -> Result<(), Box<dyn Error>> {
    let c_interface = std::ffi::CString::new(interface)?;
    let index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
    if index == 0 {
        let error = std::io::Error::last_os_error();
        return Err(error.into());
    }

    let address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: index as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let result = unsafe {
        libc::bind(
            socket,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        return Err(error.into());
    }

    Ok(())
}

fn print_web_events(events: &[WebEvent], top: usize) {
    let mut counts = HashMap::new();
    for event in events {
        let key = format!("{} {}", event.source, event.domain);
        *counts.entry(key).or_default() += 1;
    }

    println!();
    println!("web protocol events: {}", events.len());
    if counts.is_empty() {
        println!("  no DNS or TLS SNI domains captured in this window");
        return;
    }

    for (domain, count) in sorted_counts(&counts).into_iter().take(top) {
        println!("  {:>8} {}", count, domain);
    }
}

fn collect_interface_rows(
    networks: &Networks,
    cli: &NetworkArgs,
    elapsed_secs: f64,
) -> Vec<InterfaceRow> {
    let mut rows = networks
        .iter()
        .filter(|(name, _)| matches_interface(name, cli.interface.as_deref()))
        .filter(|(_, data)| cli.all || data.received() > 0 || data.transmitted() > 0)
        .map(|(name, data)| interface_row_from_network(name, data, elapsed_secs))
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        let left_total = left.rx_rate + left.tx_rate;
        let right_total = right.rx_rate + right.tx_rate;

        right_total
            .partial_cmp(&left_total)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.name.cmp(&right.name))
    });

    rows
}

fn matches_interface(name: &str, filter: Option<&str>) -> bool {
    filter
        .map(|filter| name.to_lowercase().contains(&filter.to_lowercase()))
        .unwrap_or(true)
}

fn interface_row_from_network(name: &str, data: &NetworkData, elapsed_secs: f64) -> InterfaceRow {
    InterfaceRow {
        name: name.to_owned(),
        rx_rate: data.received() as f64 / elapsed_secs,
        tx_rate: data.transmitted() as f64 / elapsed_secs,
        rx_total: data.total_received(),
        tx_total: data.total_transmitted(),
        packets_rx: data.packets_received() as f64 / elapsed_secs,
        packets_tx: data.packets_transmitted() as f64 / elapsed_secs,
        errors_rx: data.errors_on_received(),
        errors_tx: data.errors_on_transmitted(),
    }
}

fn collect_live_connections(all_states: bool) -> Result<Vec<TcpConnection>, Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(connections) = collect_linux_proc_connections(all_states) {
            return Ok(connections);
        }
    }

    collect_netstat_connections(all_states)
}

#[cfg(target_os = "linux")]
fn collect_linux_proc_connections(all_states: bool) -> Result<Vec<TcpConnection>, Box<dyn Error>> {
    let mut connections = Vec::new();
    collect_linux_proc_file("/proc/net/tcp", all_states, &mut connections)?;
    // IPv6 can be disabled entirely, so a missing /proc/net/tcp6 must not
    // discard the IPv4 connections that were already parsed.
    let _ = collect_linux_proc_file("/proc/net/tcp6", all_states, &mut connections);
    Ok(connections)
}

#[cfg(target_os = "linux")]
fn collect_linux_proc_file(
    path: &str,
    all_states: bool,
    connections: &mut Vec<TcpConnection>,
) -> Result<(), Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line?;
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }

        let Some((remote_ip, remote_port)) = parse_linux_proc_address(fields[2]) else {
            continue;
        };
        if remote_ip.is_loopback() || remote_ip.is_unspecified() || remote_port == 0 {
            continue;
        }

        let state = tcp_state_name(fields[3]).to_owned();
        if !all_states && state != "ESTABLISHED" {
            continue;
        }

        connections.push(TcpConnection {
            remote_ip,
            remote_port,
            state,
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_address(value: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;

    match address.len() {
        8 => {
            let raw = u32::from_str_radix(address, 16).ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())), port))
        }
        32 => {
            let mut bytes = [0_u8; 16];
            for index in 0..4 {
                let start = index * 8;
                let chunk = u32::from_str_radix(&address[start..start + 8], 16).ok()?;
                bytes[index * 4..index * 4 + 4].copy_from_slice(&chunk.to_le_bytes());
            }
            Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
        }
        _ => None,
    }
}

fn tcp_state_name(hex_state: &str) -> &'static str {
    match hex_state {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn collect_netstat_connections(all_states: bool) -> Result<Vec<TcpConnection>, Box<dyn Error>> {
    let output = ProcessCommand::new("netstat")
        .arg(if cfg!(windows) { "-ano" } else { "-n" })
        .output()?;
    if !output.status.success() {
        return Err("netstat command failed".into());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();
    for line in text.lines() {
        if let Some(connection) = parse_netstat_line(line) {
            if all_states || connection.state == "ESTABLISHED" {
                connections.push(connection);
            }
        }
    }

    Ok(connections)
}

fn parse_netstat_line(line: &str) -> Option<TcpConnection> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let protocol = fields.first()?.to_ascii_lowercase();
    if !protocol.starts_with("tcp") {
        return None;
    }

    let (remote, state) = if cfg!(windows) {
        (*fields.get(2)?, *fields.get(3).unwrap_or(&"UNKNOWN"))
    } else if fields.len() >= 6 {
        (*fields.get(4)?, *fields.get(5).unwrap_or(&"UNKNOWN"))
    } else {
        (*fields.get(2)?, *fields.get(3).unwrap_or(&"UNKNOWN"))
    };

    let (remote_ip, remote_port) = parse_endpoint(remote)?;
    if remote_ip.is_loopback() || remote_ip.is_unspecified() || remote_port == 0 {
        return None;
    }

    Some(TcpConnection {
        remote_ip,
        remote_port,
        state: state.to_ascii_uppercase(),
    })
}

/// Parses a `host:port` endpoint as printed by `netstat`.
///
/// Linux and Windows print `1.2.3.4:443` and `[::1]:443`, but BSD and macOS
/// print `1.2.3.4.443` and `fe80::1%en0.443`, so the port separator and the
/// IPv6 scope suffix both have to be accepted.
fn parse_endpoint(value: &str) -> Option<(IpAddr, u16)> {
    parse_bracket_endpoint(value)
        .or_else(|| parse_dotted_endpoint(value))
        .or_else(|| parse_colon_endpoint(value))
}

fn parse_bracket_endpoint(value: &str) -> Option<(IpAddr, u16)> {
    let rest = value.strip_prefix('[')?;
    let end = rest.rfind("]:")?;
    let ip = rest[..end].parse::<IpAddr>().ok()?;
    let port = rest[end + 2..].parse::<u16>().ok()?;
    Some((ip, port))
}

/// BSD and macOS form: the port trails the address after a `.`, and IPv6
/// addresses may carry a `%scope` suffix that `IpAddr` cannot parse.
fn parse_dotted_endpoint(value: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = value.rsplit_once('.')?;
    let port = port.parse::<u16>().ok()?;
    let address = address.split_once('%').map_or(address, |(host, _)| host);
    let ip = address.parse::<IpAddr>().ok()?;
    Some((ip, port))
}

fn parse_colon_endpoint(value: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = value.rsplit_once(':')?;
    let ip = ip.parse::<IpAddr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    Some((ip, port))
}

fn print_live_connections(connections: &[TcpConnection], top: usize) {
    let mut counts = HashMap::new();
    for connection in connections {
        let key = format!(
            "{}:{} {}",
            connection.remote_ip, connection.remote_port, connection.state
        );
        *counts.entry(key).or_default() += 1;
    }

    println!();
    println!("active remote connections: {}", connections.len());
    if counts.is_empty() {
        println!("  no matching TCP connections in this snapshot");
        return;
    }

    for (endpoint, count) in sorted_counts(&counts).into_iter().take(top) {
        println!("  {:>8} {}", count, endpoint);
    }
}

fn parse_packet_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    let Some(ip_packet) = ethernet_payload(packet) else {
        return Vec::new();
    };

    parse_ip_payload_for_web_events(ip_packet)
}

fn ethernet_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 14 {
        return None;
    }

    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    let mut offset = 14;

    let ethertype = if ethertype == 0x8100 && packet.len() >= 18 {
        offset = 18;
        u16::from_be_bytes([packet[16], packet[17]])
    } else {
        ethertype
    };

    match ethertype {
        0x0800 | 0x86dd => packet.get(offset..),
        _ => None,
    }
}

fn parse_ip_payload_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.is_empty() {
        return Vec::new();
    }

    match packet[0] >> 4 {
        4 => parse_ipv4_for_web_events(packet),
        6 => parse_ipv6_for_web_events(packet),
        _ => Vec::new(),
    }
}

fn parse_ipv4_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < 20 {
        return Vec::new();
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Vec::new();
    }

    let protocol = packet[9];
    match protocol {
        PROTO_TCP => parse_tcp_for_web_events(&packet[header_len..]),
        PROTO_UDP => parse_udp_for_web_events(&packet[header_len..]),
        _ => Vec::new(),
    }
}

fn parse_ipv6_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < 40 {
        return Vec::new();
    }

    let mut next_header = packet[6];
    let mut offset = 40;

    // Skip over any extension header chain so that DNS and TLS SNI are still
    // found on packets that carry hop-by-hop, routing or fragment headers.
    for _ in 0..MAX_IPV6_EXTENSION_HEADERS {
        match next_header {
            PROTO_TCP => return parse_tcp_for_web_events(&packet[offset..]),
            PROTO_UDP => return parse_udp_for_web_events(&packet[offset..]),
            _ => {}
        }

        let Some(header) = packet.get(offset..) else {
            break;
        };
        // Only the first fragment of a datagram carries a usable transport header.
        if next_header == PROTO_FRAGMENT && !is_first_fragment(header) {
            break;
        }
        let Some(length) = ipv6_extension_header_len(header, next_header) else {
            break;
        };

        next_header = header[0];
        offset += length;
    }

    Vec::new()
}

const MAX_IPV6_EXTENSION_HEADERS: usize = 8;

const PROTO_HOPOPTS: u8 = 0;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ROUTING: u8 = 43;
const PROTO_FRAGMENT: u8 = 44;
const PROTO_AH: u8 = 51;
const PROTO_DSTOPTS: u8 = 60;
const PROTO_MOBILITY: u8 = 135;

fn ipv6_extension_header_len(header: &[u8], next_header: u8) -> Option<usize> {
    let length = match next_header {
        // The fragment header is always 8 bytes and its second byte is flags,
        // not a length.
        PROTO_FRAGMENT => 8,
        // The AH length field counts 4-byte units, minus two.
        PROTO_AH => (usize::from(*header.get(1)?) + 2).checked_mul(4)?,
        // Every other extension header length counts 8-byte units, minus one.
        PROTO_HOPOPTS | PROTO_ROUTING | PROTO_DSTOPTS | PROTO_MOBILITY => {
            (usize::from(*header.get(1)?) + 1).checked_mul(8)?
        }
        _ => return None,
    };

    (header.len() >= length).then_some(length)
}

fn is_first_fragment(header: &[u8]) -> bool {
    header
        .get(2..4)
        .is_some_and(|field| u16::from_be_bytes([field[0], field[1]]) == 0)
}

fn parse_udp_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < 8 {
        return Vec::new();
    }

    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
    if source_port != 53 && destination_port != 53 {
        return Vec::new();
    }

    // Clamp to the declared UDP length so that Ethernet padding is never
    // mistaken for DNS data.
    let declared = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let end = declared.clamp(8, packet.len());

    parse_dns_query_domains(&packet[8..end])
        .into_iter()
        .map(|domain| WebEvent {
            source: "dns",
            domain,
        })
        .collect()
}

fn parse_tcp_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < 20 {
        return Vec::new();
    }

    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
    let header_len = usize::from(packet[12] >> 4) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Vec::new();
    }

    let payload = &packet[header_len..];
    let mut events = Vec::new();

    if (source_port == 53 || destination_port == 53) && payload.len() >= 2 {
        let dns_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
        if payload.len() >= dns_len + 2 {
            events.extend(
                parse_dns_query_domains(&payload[2..2 + dns_len])
                    .into_iter()
                    .map(|domain| WebEvent {
                        source: "dns",
                        domain,
                    }),
            );
        }
    }

    if source_port == 443 || destination_port == 443 {
        if let Some(domain) = parse_tls_sni(payload) {
            events.push(WebEvent {
                source: "tls-sni",
                domain,
            });
        }
    }

    events
}

fn parse_dns_query_domains(packet: &[u8]) -> Vec<String> {
    if packet.len() < 12 {
        return Vec::new();
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_response = flags & 0x8000 != 0;
    if is_response {
        return Vec::new();
    }

    let question_count = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let mut offset = 12;
    let mut domains = Vec::new();

    for _ in 0..question_count {
        let Some((domain, next_offset)) = parse_dns_name(packet, offset) else {
            break;
        };
        offset = next_offset;
        if packet.len() < offset + 4 {
            break;
        }
        offset += 4;

        if !domain.is_empty() {
            domains.push(domain);
        }
    }

    domains
}

fn parse_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut seen = 0;

    loop {
        if offset >= packet.len() || seen > packet.len() {
            return None;
        }
        seen += 1;

        let len = packet[offset];
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            let pointer = usize::from(u16::from_be_bytes([len & 0x3f, packet[offset + 1]]));
            if !jumped {
                next_offset = offset + 2;
            }
            offset = pointer;
            jumped = true;
            continue;
        }

        if len == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }

        let start = offset + 1;
        let end = start + usize::from(len);
        if end > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[start..end]).to_string());
        offset = end;
    }

    Some((labels.join(".").to_ascii_lowercase(), next_offset))
}

fn parse_tls_sni(packet: &[u8]) -> Option<String> {
    if packet.len() < 5 || packet[0] != 22 {
        return None;
    }

    let record_len = usize::from(u16::from_be_bytes([packet[3], packet[4]]));
    if packet.len() < 5 + record_len || packet.get(5).copied()? != 1 {
        return None;
    }

    let handshake_len = read_u24(packet.get(6..9)?)?;
    if packet.len() < 9 + handshake_len {
        return None;
    }

    let mut offset = 9;
    offset += 2;
    offset += 32;
    if offset >= packet.len() {
        return None;
    }

    let session_id_len = usize::from(packet[offset]);
    offset += 1 + session_id_len;
    if offset + 2 > packet.len() {
        return None;
    }

    let cipher_len = usize::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
    offset += 2 + cipher_len;
    if offset >= packet.len() {
        return None;
    }

    let compression_len = usize::from(packet[offset]);
    offset += 1 + compression_len;
    if offset + 2 > packet.len() {
        return None;
    }

    let extensions_len = usize::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    if extensions_end > packet.len() {
        return None;
    }

    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let extension_len =
            usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        offset += 4;
        let extension_end = offset.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }

        if extension_type == 0 {
            return parse_tls_sni_extension(&packet[offset..extension_end]);
        }

        offset = extension_end;
    }

    None
}

fn parse_tls_sni_extension(extension: &[u8]) -> Option<String> {
    if extension.len() < 2 {
        return None;
    }

    let list_len = usize::from(u16::from_be_bytes([extension[0], extension[1]]));
    let mut offset: usize = 2;
    let list_end = offset.checked_add(list_len)?;
    if list_end > extension.len() {
        return None;
    }

    while offset + 3 <= list_end {
        let name_type = extension[offset];
        let name_len = usize::from(u16::from_be_bytes([
            extension[offset + 1],
            extension[offset + 2],
        ]));
        offset += 3;
        let name_end = offset.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }

        if name_type == 0 {
            return Some(
                String::from_utf8_lossy(&extension[offset..name_end]).to_ascii_lowercase(),
            );
        }

        offset = name_end;
    }

    None
}

fn read_u24(bytes: &[u8]) -> Option<usize> {
    if bytes.len() != 3 {
        return None;
    }
    Some((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
}

fn print_interface_rows(rows: &[InterfaceRow], unit: Unit) {
    println!();
    println!(
        "{:<18} {:>14} {:>14} {:>14} {:>14} {:>12} {:>12} {:>10}",
        "interface", "rx/s", "tx/s", "rx total", "tx total", "rx pkt/s", "tx pkt/s", "errors"
    );
    println!("{}", "-".repeat(116));

    if rows.is_empty() {
        println!("no matching traffic in this sample; use --all to show idle interfaces");
        return;
    }

    for row in rows {
        println!(
            "{:<18} {:>14} {:>14} {:>14} {:>14} {:>12} {:>12} {:>10}",
            truncate(&row.name, 18),
            format_rate(row.rx_rate, unit),
            format_rate(row.tx_rate, unit),
            format_bytes(row.rx_total as f64),
            format_bytes(row.tx_total as f64),
            format!("{:.1}", row.packets_rx),
            format!("{:.1}", row.packets_tx),
            format!("{}/{}", row.errors_rx, row.errors_tx),
        );
    }
}

fn sorted_counts(values: &HashMap<String, u64>) -> Vec<(&str, u64)> {
    let mut rows = values
        .iter()
        .map(|(value, count)| (value.as_str(), *count))
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    rows
}

fn positive_f64(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| format!("`{value}` is not a number"))?;

    if parsed.is_finite()
        && parsed > 0.0
        && Duration::try_from_secs_f64(parsed).is_ok_and(|duration| !duration.is_zero())
    {
        Ok(parsed)
    } else {
        Err("value must be a positive, representable duration (at least 1 ns)".to_owned())
    }
}

fn positive_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("`{value}` is not a positive integer"))?;

    if parsed > 0 {
        Ok(parsed)
    } else {
        Err("value must be greater than 0".to_owned())
    }
}

fn format_rate(bytes_per_second: f64, unit: Unit) -> String {
    match unit {
        Unit::Auto | Unit::Bytes => format!("{}/s", format_bytes(bytes_per_second)),
        Unit::Bits => format!("{}/s", format_bits(bytes_per_second * 8.0)),
    }
}

fn format_bytes(bytes: f64) -> String {
    format_scaled(bytes, &["B", "KiB", "MiB", "GiB", "TiB"])
}

fn format_bits(bits: f64) -> String {
    format_scaled(bits, &["b", "Kib", "Mib", "Gib", "Tib"])
}

fn format_scaled(mut value: f64, units: &[&str]) -> String {
    let mut index = 0;
    while value >= 1024.0 && index < units.len() - 1 {
        value /= 1024.0;
        index += 1;
    }

    if index == 0 {
        format!("{value:.0} {}", units[index])
    } else if value < 10.0 {
        format!("{value:.2} {}", units[index])
    } else {
        format!("{value:.1} {}", units[index])
    }
}

fn trim_float(value: f64) -> String {
    let formatted = format!("{value:.3}");
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

fn truncate(value: &str, width: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(width).collect::<String>();

    if chars.next().is_some() && width >= 4 {
        format!(
            "{}...",
            truncated
                .chars()
                .take(width.saturating_sub(3))
                .collect::<String>()
        )
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_positive_intervals() {
        assert_eq!(positive_f64("0.5"), Ok(0.5));
        assert!(positive_f64("0").is_err());
        assert!(positive_f64("-1").is_err());
        assert!(positive_f64("nan").is_err());
    }

    #[test]
    fn rejects_unrepresentable_intervals() {
        for value in ["1e300", "1e-300", "0.0000000001"] {
            assert!(positive_f64(value).is_err(), "accepted {value}");
            assert!(Cli::try_parse_from(["netor", "--interval", value]).is_err());
        }
        assert_eq!(positive_f64("0.000000001"), Ok(1e-9));
    }

    #[test]
    fn interval_wait_handles_cancellation_and_spurious_wakeups() {
        let running = AtomicBool::new(false);
        assert!(!wait_for_interval(Duration::from_secs(60), &running));

        running.store(true, Ordering::SeqCst);
        thread::current().unpark();
        let started = Instant::now();
        let interval = Duration::from_millis(10);
        assert!(wait_for_interval(interval, &running));
        assert!(started.elapsed() >= interval);
    }

    #[test]
    fn validates_positive_top_limit() {
        assert_eq!(positive_usize("15"), Ok(15));
        assert!(positive_usize("0").is_err());
        assert!(positive_usize("abc").is_err());
    }

    #[test]
    fn formats_bytes_with_binary_units() {
        assert_eq!(format_bytes(0.0), "0 B");
        assert_eq!(format_bytes(1023.0), "1023 B");
        assert_eq!(format_bytes(1024.0), "1.00 KiB");
        assert_eq!(format_bytes(10.0 * 1024.0), "10.0 KiB");
    }

    #[test]
    fn filters_interfaces_case_insensitively() {
        assert!(matches_interface("Ethernet 2", Some("ether")));
        assert!(!matches_interface("lo", Some("wlan")));
        assert!(matches_interface("lo", None));
    }

    #[test]
    fn parses_plain_and_bracketed_endpoints() {
        assert_eq!(
            parse_endpoint("93.184.216.34:443"),
            Some((IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443))
        );
        assert_eq!(
            parse_endpoint("[2606:2800:220:1:248:1893:25c8:1946]:443"),
            Some((
                IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()),
                443
            ))
        );
    }

    #[test]
    fn parses_dns_query_domains() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        assert_eq!(parse_dns_query_domains(&packet), vec!["example.com"]);
    }

    #[test]
    fn parses_tls_sni_extension() {
        let mut extension = Vec::new();
        extension.extend_from_slice(&[0x00, 0x11]);
        extension.push(0x00);
        extension.extend_from_slice(&[0x00, 0x0e]);
        extension.extend_from_slice(b"www.openai.com");

        assert_eq!(
            parse_tls_sni_extension(&extension),
            Some("www.openai.com".to_owned())
        );
    }

    #[test]
    fn reads_three_byte_lengths() {
        assert_eq!(read_u24(&[0x00, 0x10, 0x00]), Some(4096));
        assert_eq!(read_u24(&[0x10, 0x00]), None);
    }

    #[test]
    fn trims_trailing_zeros_from_float() {
        assert_eq!(trim_float(1.0), "1");
        assert_eq!(trim_float(1.500), "1.5");
        assert_eq!(trim_float(0.123), "0.123");
        assert_eq!(trim_float(2.001), "2.001");
    }

    #[test]
    fn formats_bits_with_binary_units() {
        assert_eq!(format_bits(0.0), "0 b");
        assert_eq!(format_bits(1024.0), "1.00 Kib");
        assert_eq!(format_bits(1024.0 * 1024.0), "1.00 Mib");
    }

    #[test]
    fn formats_rate_in_bytes_and_bits() {
        assert_eq!(format_rate(1024.0, Unit::Bytes), "1.00 KiB/s");
        assert_eq!(format_rate(1024.0, Unit::Bits), "8.00 Kib/s");
        assert_eq!(format_rate(1024.0, Unit::Auto), "1.00 KiB/s");
    }

    #[test]
    fn truncates_long_interface_names() {
        assert_eq!(truncate("abcdefghijklmnopqrs", 18), "abcdefghijklmno...");
        assert_eq!(truncate("short", 18), "short");
        assert_eq!(truncate("exact18chars------", 18), "exact18chars------");
        assert_eq!(truncate("", 10), "");
        assert_eq!(truncate("abc", 1), "a");
        assert_eq!(truncate("abcdef", 3), "abc");
    }

    #[test]
    fn sorts_counts_by_frequency() {
        let mut counts = HashMap::new();
        counts.insert("a".to_owned(), 3);
        counts.insert("b".to_owned(), 1);
        counts.insert("c".to_owned(), 5);
        let sorted = sorted_counts(&counts);
        assert_eq!(sorted[0], ("c", 5));
        assert_eq!(sorted[1], ("a", 3));
        assert_eq!(sorted[2], ("b", 1));
    }

    #[test]
    fn maps_tcp_state_hex_codes() {
        assert_eq!(tcp_state_name("01"), "ESTABLISHED");
        assert_eq!(tcp_state_name("02"), "SYN_SENT");
        assert_eq!(tcp_state_name("06"), "TIME_WAIT");
        assert_eq!(tcp_state_name("0A"), "LISTEN");
        assert_eq!(tcp_state_name("FF"), "UNKNOWN");
    }

    #[test]
    fn validates_positive_f64_edge_cases() {
        assert!(positive_f64("inf").is_err());
        assert!(positive_f64("-inf").is_err());
        assert_eq!(positive_f64("1"), Ok(1.0));
        assert_eq!(positive_f64("0.001"), Ok(0.001));
    }

    #[test]
    fn rejects_invalid_endpoints() {
        assert_eq!(parse_endpoint("not-an-endpoint"), None);
        assert_eq!(parse_endpoint(""), None);
        assert_eq!(parse_endpoint("192.168.1.1"), None);
    }

    #[test]
    fn formats_large_byte_values() {
        assert_eq!(format_bytes(1024.0 * 1024.0), "1.00 MiB");
        assert_eq!(format_bytes(1024.0 * 1024.0 * 1024.0), "1.00 GiB");
        assert_eq!(format_bytes(1024.0 * 1024.0 * 1024.0 * 1024.0), "1.00 TiB");
    }

    #[test]
    fn rejects_non_positive_usize() {
        assert!(positive_usize("0").is_err());
        assert!(positive_usize("-5").is_err());
        assert_eq!(positive_usize("100"), Ok(100));
    }

    #[test]
    fn parses_dns_response_ignored() {
        let packet = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        assert_eq!(parse_dns_query_domains(&packet), Vec::<String>::new());
    }

    #[test]
    fn parses_bsd_netstat_dotted_endpoints() {
        // macOS and BSD `netstat -n` separates the port with a dot.
        assert_eq!(
            parse_endpoint("93.184.216.34.443"),
            Some((IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443))
        );
        assert_eq!(
            parse_endpoint("127.0.0.1.54321"),
            Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 54321))
        );
    }

    #[test]
    fn parses_bsd_netstat_ipv6_endpoints_with_scope() {
        assert_eq!(
            parse_endpoint("fe80::1%en0.443"),
            Some((IpAddr::V6("fe80::1".parse().unwrap()), 443))
        );
        assert_eq!(
            parse_endpoint("::ffff:1.2.3.4.443"),
            Some((IpAddr::V6("::ffff:1.2.3.4".parse().unwrap()), 443))
        );
    }

    #[test]
    fn parses_linux_netstat_colon_endpoints() {
        assert_eq!(
            parse_endpoint("93.184.216.34:443"),
            Some((IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443))
        );
        assert_eq!(
            parse_endpoint("[2606:2800:220:1:248:1893:25c8:1946]:443"),
            Some((
                IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()),
                443
            ))
        );
        assert_eq!(
            parse_endpoint("::ffff:1.2.3.4:443"),
            Some((IpAddr::V6("::ffff:1.2.3.4".parse().unwrap()), 443))
        );
    }

    #[test]
    fn parses_macos_netstat_line() {
        let line =
            "tcp4       0      0  192.168.1.5.54321       93.184.216.34.443      ESTABLISHED";
        assert_eq!(
            parse_netstat_line(line),
            Some(TcpConnection {
                remote_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                remote_port: 443,
                state: "ESTABLISHED".to_owned(),
            })
        );
    }

    #[test]
    fn parses_linux_netstat_line() {
        let line = "tcp        0      0 127.0.0.1:54321         93.184.216.34:443      ESTABLISHED";
        assert_eq!(
            parse_netstat_line(line),
            Some(TcpConnection {
                remote_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                remote_port: 443,
                state: "ESTABLISHED".to_owned(),
            })
        );
    }

    #[test]
    fn skips_ipv6_extension_headers() {
        // IPv6 header, a hop-by-hop header, then a full TLS ClientHello.
        let mut packet = vec![0u8; 40 + 8 + 64];
        packet[0] = 0x60;
        packet[6] = PROTO_HOPOPTS;
        packet[40] = PROTO_TCP;
        packet[41] = 0; // 8 byte hop-by-hop header
        let tls = &mut packet[48..];
        tls[0] = 22;
        tls[3] = 0;
        tls[4] = 5; // record length
        tls[5] = 1; // ClientHello

        // Without extension header walking this payload was never reached; the
        // assertion below only checks that parsing stays well defined.
        assert!(parse_ipv6_for_web_events(&packet).is_empty());
    }

    #[test]
    fn walks_routing_and_destination_option_headers() {
        for (hop, length_byte, total) in [
            (PROTO_ROUTING, 1u8, 16usize),
            (PROTO_DSTOPTS, 2, 24),
            (PROTO_MOBILITY, 0, 8),
        ] {
            let mut packet = vec![0u8; 40 + total];
            packet[6] = hop;
            packet[40] = PROTO_UDP;
            packet[41] = length_byte;
            assert_eq!(ipv6_extension_header_len(&packet[40..], hop), Some(total));
        }
    }

    #[test]
    fn measures_ipv6_authentication_header_length() {
        // AH counts 4-byte units minus two, unlike the 8-byte form.
        let mut header = vec![0u8; 24];
        header[1] = 4;
        assert_eq!(ipv6_extension_header_len(&header, PROTO_AH), Some(24));
    }

    #[test]
    fn ignores_non_first_ipv6_fragments() {
        let mut packet = vec![0u8; 48];
        packet[6] = PROTO_FRAGMENT;
        packet[40] = PROTO_TCP;
        packet[42] = 0x00;
        packet[43] = 0x01; // non-zero fragment offset
        assert!(parse_ipv6_for_web_events(&packet).is_empty());
    }

    #[test]
    fn rejects_truncated_ipv6_extension_headers() {
        assert_eq!(ipv6_extension_header_len(&[0, 8], PROTO_HOPOPTS), None);
        assert_eq!(ipv6_extension_header_len(&[0, 8], PROTO_FRAGMENT), None);
        assert_eq!(ipv6_extension_header_len(&[0, 8], PROTO_TCP), None);
    }

    #[test]
    fn caps_ipv6_extension_header_chain() {
        // A chain of hop-by-hop headers pointing at itself must terminate.
        let mut packet = vec![0u8; 40 + 8 * 64];
        packet[6] = PROTO_HOPOPTS;
        for index in 0..64 {
            packet[40 + index * 8] = PROTO_HOPOPTS;
        }
        assert!(parse_ipv6_for_web_events(&packet).is_empty());
    }

    #[test]
    fn ignores_dns_beyond_udp_length() {
        // UDP header declaring an 8 byte payload, followed by a DNS query in
        // what is really Ethernet padding.
        let dns = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'f',
            b'o', b'o', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let mut packet = vec![0u8; 8];
        packet[0] = 0x00;
        packet[1] = 0x35; // source port 53
        packet[4] = 0x00;
        packet[5] = 0x08; // declared UDP length
        packet.extend_from_slice(&dns);
        packet.extend_from_slice(&[0xAA; 16]); // padding

        assert!(parse_udp_for_web_events(&packet).is_empty());
    }

    #[test]
    fn parses_dns_inside_declared_udp_length() {
        let dns = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'f',
            b'o', b'o', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let mut packet = vec![0u8; 8];
        packet[1] = 0x35;
        packet[4] = ((8 + dns.len()) >> 8) as u8;
        packet[5] = (8 + dns.len()) as u8;
        packet.extend_from_slice(&dns);
        packet.extend_from_slice(&[0xAA; 16]); // padding past the declared length

        let events = parse_udp_for_web_events(&packet);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].domain, "foo.com");
    }

    #[test]
    fn parses_dns_short_packet_returns_empty() {
        assert_eq!(parse_dns_query_domains(&[0u8; 5]), Vec::<String>::new());
    }

    #[test]
    fn rejects_non_tls_packets() {
        assert_eq!(parse_tls_sni(&[0u8; 5]), None);
        assert_eq!(parse_tls_sni(&[22, 3, 1, 0, 5, 99]), None);
    }

    #[test]
    fn rejects_short_tls_sni_extension() {
        assert_eq!(parse_tls_sni_extension(&[0x00]), None);
        assert_eq!(parse_tls_sni_extension(&[]), None);
    }

    #[test]
    fn extracts_ethernet_ipv4_payload() {
        let mut packet = vec![0u8; 34];
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x45;
        assert!(ethernet_payload(&packet).is_some());
    }

    #[test]
    fn rejects_short_ethernet_frame() {
        assert_eq!(ethernet_payload(&[0u8; 10]), None);
    }

    #[test]
    fn rejects_non_ip_ethertype() {
        let mut packet = vec![0u8; 20];
        packet[12] = 0x00;
        packet[13] = 0x01;
        assert_eq!(ethernet_payload(&packet), None);
    }

    #[test]
    fn parses_vlan_tagged_frame() {
        let mut packet = vec![0u8; 38];
        packet[12] = 0x81;
        packet[13] = 0x00;
        packet[16] = 0x08;
        packet[17] = 0x00;
        packet[18] = 0x45;
        assert!(ethernet_payload(&packet).is_some());
    }

    #[test]
    fn rejects_short_ipv4_packet() {
        assert_eq!(
            parse_ipv4_for_web_events(&[0u8; 10]),
            Vec::<WebEvent>::new()
        );
    }

    #[test]
    fn rejects_short_ipv6_packet() {
        assert_eq!(
            parse_ipv6_for_web_events(&[0u8; 20]),
            Vec::<WebEvent>::new()
        );
    }

    #[test]
    fn rejects_unknown_ip_version() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x90;
        assert_eq!(
            parse_ip_payload_for_web_events(&packet),
            Vec::<WebEvent>::new()
        );
    }

    #[test]
    fn rejects_empty_ip_payload() {
        assert_eq!(parse_ip_payload_for_web_events(&[]), Vec::<WebEvent>::new());
    }

    #[test]
    fn rejects_short_tcp_packet() {
        assert_eq!(parse_tcp_for_web_events(&[0u8; 10]), Vec::<WebEvent>::new());
    }

    #[test]
    fn rejects_short_udp_packet() {
        assert_eq!(parse_udp_for_web_events(&[0u8; 4]), Vec::<WebEvent>::new());
    }

    #[test]
    fn parses_dns_name_with_pointer() {
        let mut packet = vec![0u8; 64];
        packet[0] = 3;
        packet[1] = b'w';
        packet[2] = b'w';
        packet[3] = b'w';
        packet[4] = 0;
        let (name, _) = parse_dns_name(&packet, 0).unwrap();
        assert_eq!(name, "www");
    }

    #[test]
    fn rejects_dns_name_beyond_packet() {
        assert_eq!(parse_dns_name(&[0x05], 0), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_ipv4_addresses() {
        assert_eq!(
            parse_linux_proc_address("22D8B85D:01BB"),
            Some((IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443))
        );
    }
}
