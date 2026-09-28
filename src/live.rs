//! Live TCP connection snapshots from the operating system connection table.

use crate::tally::sorted_counts;
use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command as ProcessCommand;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpConnection {
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub state: String,
}

pub fn collect_live_connections(all_states: bool) -> Result<Vec<TcpConnection>, Box<dyn Error>> {
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

pub fn tcp_state_name(hex_state: &str) -> &'static str {
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

pub fn parse_netstat_line(line: &str) -> Option<TcpConnection> {
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

pub fn print_live_connections(connections: &[TcpConnection], top: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
            parse_endpoint("::ffff:1.2.3.4:443"),
            Some((IpAddr::V6("::ffff:1.2.3.4".parse().unwrap()), 443))
        );
    }

    #[test]
    fn rejects_invalid_endpoints() {
        assert_eq!(parse_endpoint("not-an-endpoint"), None);
        assert_eq!(parse_endpoint(""), None);
        assert_eq!(parse_endpoint("192.168.1.1"), None);
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
    fn ignores_non_tcp_and_loopback_netstat_lines() {
        assert_eq!(parse_netstat_line("udp4  0  0  *.5353  *.*"), None);
        assert_eq!(
            parse_netstat_line("tcp4  0  0  127.0.0.1.54321  127.0.0.1.54322  ESTABLISHED"),
            None
        );
    }

    #[test]
    fn maps_tcp_state_hex_codes() {
        assert_eq!(tcp_state_name("01"), "ESTABLISHED");
        assert_eq!(tcp_state_name("02"), "SYN_SENT");
        assert_eq!(tcp_state_name("06"), "TIME_WAIT");
        assert_eq!(tcp_state_name("0A"), "LISTEN");
        assert_eq!(tcp_state_name("FF"), "UNKNOWN");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_ipv4_addresses() {
        assert_eq!(
            parse_linux_proc_address("22D8B85D:01BB"),
            Some((IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_ipv6_addresses() {
        // /proc/net/tcp6 stores four little-endian 32-bit words.
        assert_eq!(
            parse_linux_proc_address("00000000000000000000000001000000:01BB"),
            Some((IpAddr::V6("::1".parse().unwrap()), 443))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_malformed_linux_proc_addresses() {
        assert_eq!(parse_linux_proc_address(""), None);
        assert_eq!(parse_linux_proc_address("ZZZZ:01BB"), None);
        assert_eq!(parse_linux_proc_address("22D8B85D"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_the_real_proc_connection_table() {
        // The host always has at least a loopback listener, so the table must
        // parse without error even when every row is filtered out.
        let mut connections = Vec::new();
        collect_linux_proc_file("/proc/net/tcp", true, &mut connections).expect("readable");
        for connection in &connections {
            assert!(!connection.remote_ip.is_loopback());
            assert_ne!(connection.remote_port, 0);
        }
    }
}
