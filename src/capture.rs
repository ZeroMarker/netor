//! Packet capture backends: Linux raw sockets and Windows Npcap.

use crate::proto::WebEvent;
use crate::tally::sorted_counts;
use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(target_os = "linux")]
pub fn capture_web_events(
    duration: Duration,
    interface: Option<&str>,
    running: &AtomicBool,
) -> Result<Vec<WebEvent>, Box<dyn Error>> {
    let socket = open_packet_socket(interface)?;
    let started = std::time::Instant::now();
    let mut buffer = vec![0_u8; 65_536];
    let mut events = Vec::new();

    while running.load(std::sync::atomic::Ordering::SeqCst) && started.elapsed() < duration {
        let read = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };

        if read > 0 {
            events.extend(crate::proto::parse_packet_for_web_events(
                &buffer[..read as usize],
            ));
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
pub fn capture_web_events(
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

    let started = std::time::Instant::now();
    let mut events = Vec::new();

    while running.load(std::sync::atomic::Ordering::SeqCst) && started.elapsed() < duration {
        match cap.next_packet() {
            Ok(packet) => {
                events.extend(crate::proto::parse_packet_for_web_events(packet.data));
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
pub fn capture_web_events(
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

pub fn print_web_events(events: &[WebEvent], top: usize) {
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
        println!("  {:>8} {}", domain, count);
    }
}
