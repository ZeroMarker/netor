//! Packet capture backends: Linux raw sockets and Windows Npcap.
//!
//! A [`Capture`] is opened once and reused for every window. Opening a fresh
//! raw socket per window would drop everything that arrived while the previous
//! socket was being torn down and replaced.

use crate::proto::{self, WebEvent};
use crate::tally::sorted_counts;
use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Size of the receive buffer. Large enough for a full jumbo frame.
const CAPTURE_BUFFER_LEN: usize = 65_536;

/// Collects domain events for one capture window.
pub fn capture_web_events(
    capture: &mut Capture,
    duration: Duration,
    running: &AtomicBool,
) -> Result<Vec<WebEvent>, Box<dyn Error>> {
    let started = Instant::now();
    let mut buffer = vec![0_u8; CAPTURE_BUFFER_LEN];
    let mut events = Vec::new();

    while running.load(Ordering::SeqCst) && started.elapsed() < duration {
        let read = capture.read(&mut buffer)?;
        if read > 0 {
            events.extend(proto::parse_packet_for_web_events(&buffer[..read]));
        }
    }

    Ok(events)
}

#[cfg(target_os = "linux")]
mod backend {
    use super::{Error, CAPTURE_BUFFER_LEN};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;

    /// How long a blocking read waits before returning so that the shutdown
    /// flag can be rechecked.
    const READ_TIMEOUT: Duration = Duration::from_millis(200);

    pub struct Capture {
        socket: OwnedFd,
    }

    impl Capture {
        pub fn open(interface: Option<&str>) -> Result<Self, Box<dyn Error>> {
            let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
            let socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
            if socket < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            // Own the descriptor immediately so every error path closes it.
            let socket = unsafe { OwnedFd::from_raw_fd(socket) };
            let capture = Capture { socket };

            capture.set_read_timeout(READ_TIMEOUT)?;
            capture.attach_filter();

            if let Some(interface) = interface {
                capture.bind(interface)?;
            }

            Ok(capture)
        }

        /// Returns the number of bytes read, or 0 if the read timed out.
        pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Box<dyn Error>> {
            debug_assert!(buffer.len() <= CAPTURE_BUFFER_LEN);
            let read = unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };

            if read >= 0 {
                return Ok(read as usize);
            }

            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
            ) {
                return Ok(0);
            }
            Err(error.into())
        }

        fn set_read_timeout(&self, timeout: Duration) -> Result<(), Box<dyn Error>> {
            let value = libc::timeval {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_usec: timeout.subsec_micros() as libc::suseconds_t,
            };
            let set = unsafe {
                libc::setsockopt(
                    self.socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&value as *const libc::timeval).cast(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if set < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }

        /// Installs a kernel-side BPF filter so that the kernel drops the
        /// packets `netor` would only discard again in userspace.
        ///
        /// This is a load filter, not a correctness filter: anything the
        /// dissector might still need is let through, and a failure here only
        /// costs performance, so it is never fatal.
        fn attach_filter(&self) {
            let program = crate::filter::INTEREST_FILTER;
            let length = libc::c_ushort::try_from(program.len()).unwrap_or(libc::c_ushort::MAX);
            let filter = libc::sock_fprog {
                len: length,
                filter: program.as_ptr().cast_mut(),
            };

            let attached = unsafe {
                libc::setsockopt(
                    self.socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ATTACH_FILTER,
                    (&filter as *const libc::sock_fprog).cast(),
                    std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
                )
            };
            if attached < 0 {
                eprintln!(
                    "netor: warning: could not attach the capture filter ({}); \
                     continuing without it",
                    std::io::Error::last_os_error()
                );
            }
        }

        fn bind(&self, interface: &str) -> Result<(), Box<dyn Error>> {
            let c_interface = std::ffi::CString::new(interface)?;
            let index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
            if index == 0 {
                return Err(std::io::Error::last_os_error().into());
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
                    self.socket.as_raw_fd(),
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub use backend::Capture;

#[cfg(all(windows, feature = "npcap"))]
mod backend {
    use super::Error;

    /// The tcpdump expression equivalent to the classic BPF program in
    /// `crate::filter`: Npcap compiles a filter from a string instead of from
    /// instructions, so this spelling of "port 53 or 443 over TCP or UDP"
    /// lives next to the backend that needs it.
    const PCAP_FILTER: &str = "(tcp or udp) and (port 53 or port 443)";

    pub struct Capture {
        inner: pcap::Capture<pcap::Active>,
    }

    impl Capture {
        pub fn open(interface: Option<&str>) -> Result<Self, Box<dyn Error>> {
            let device = select_pcap_device(interface)?;
            let inner = pcap::Capture::from_device(device)
                .map_err(|e| format!("pcap: {e}"))?
                .promisc(true)
                .snaplen(super::CAPTURE_BUFFER_LEN as i32)
                .timeout(200)
                .immediate_mode(true)
                .open()
                .map_err(|e| format!("pcap open: {e}"))?;

            let mut capture = Capture { inner };
            capture.attach_filter();
            Ok(capture)
        }

        /// Returns the number of bytes read, or 0 if the read timed out.
        pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Box<dyn Error>> {
            match self.inner.next_packet() {
                Ok(packet) => {
                    let length = packet.data.len().min(buffer.len());
                    buffer[..length].copy_from_slice(&packet.data[..length]);
                    Ok(length)
                }
                Err(pcap::Error::TimeoutExpired) => Ok(0),
                Err(error) => Err(format!("pcap: {error}").into()),
            }
        }

        /// Lets the same kernel-side filter run on Windows via Npcap, so both
        /// platforms do the same amount of work.
        fn attach_filter(&mut self) {
            if let Err(error) = self.inner.filter(PCAP_FILTER, true) {
                eprintln!(
                    "netor: warning: could not apply the capture filter ({error}); \
                     continuing without it"
                );
            }
        }
    }

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
}

#[cfg(all(windows, feature = "npcap"))]
pub use backend::Capture;

/// Placeholder for platforms with no capture support, so that `main` and the
/// CLI stay platform independent and report a clear error.
#[cfg(not(any(target_os = "linux", all(windows, feature = "npcap"))))]
pub struct Capture;

#[cfg(not(any(target_os = "linux", all(windows, feature = "npcap"))))]
impl Capture {
    pub fn open(_interface: Option<&str>) -> Result<Self, Box<dyn Error>> {
        #[cfg(windows)]
        {
            Err("packet capture requires the 'npcap' feature and Npcap installed; rebuild with --features npcap".into())
        }
        #[cfg(not(windows))]
        {
            Err("packet capture is not yet supported on this platform".into())
        }
    }

    /// Present only so the platform-independent capture loop type-checks;
    /// [`Capture::open`] fails first, so this is never reached.
    pub fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        Err("packet capture is unavailable on this platform".into())
    }
}

pub fn print_web_events(events: &[WebEvent], top: usize) {
    // Count by borrowed key so that no key string is allocated per packet.
    let mut counts: HashMap<(&str, &str), u64> = HashMap::new();
    for event in events {
        *counts
            .entry((event.source, event.domain.as_str()))
            .or_default() += 1;
    }

    println!();
    println!("web protocol events: {}", events.len());
    if counts.is_empty() {
        println!("  no DNS or TLS SNI domains captured in this window");
        return;
    }

    for ((source, domain), count) in sorted_counts(&counts).into_iter().take(top) {
        println!("  {:>8} {} {}", count, source, domain);
    }
}

/// `sock_filter` is only defined on Linux, so the instruction table is kept
/// out of the way on other platforms. The tests for that table run on every
/// platform, so they get a stand-in with the same layout.
#[cfg(all(not(target_os = "linux"), test))]
pub(crate) struct FilterInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[cfg(target_os = "linux")]
pub(crate) use libc::sock_filter as FilterInstruction;
