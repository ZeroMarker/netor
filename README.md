# netor

`netor` is a system-level network traffic monitor written in Rust.

It does not read browser history, web server logs, CDN analytics, or website
statistics. It only uses information available from the operating system:

- Network interface counters
- Live TCP connection tables
- Packet contents from DNS and TLS ClientHello SNI

## Features

- Cross-platform interface traffic statistics through `sysinfo`
- Live remote TCP endpoint monitoring without browser or server logs
- Real-time DNS and TLS SNI domain capture (Linux raw sockets, Windows Npcap)
- Receive/transmit byte and packet rates based on actual elapsed sampling time
- Traffic totals per network interface
- TCP remote IP, port, and connection state snapshots
- Continuous monitoring or one-shot output

## Usage

Show network interface traffic:

```bash
cargo run
```

Show all interfaces, including idle ones:

```bash
cargo run -- --all
```

Print one interface sample and exit:

```bash
cargo run -- --once --all --interval 0.5
```

Monitor live TCP connections:

```bash
cargo run -- live
```

Print one live TCP snapshot:

```bash
cargo run -- live --once
```

Include non-established TCP states:

```bash
cargo run -- live --once --all-states
```

Capture website domain events from DNS and TLS SNI packets:

```bash
# Linux (requires root or CAP_NET_RAW)
sudo cargo run -- web --once
sudo cargo run -- web --interface eth0 --interval 5

# Windows (requires Npcap installed)
cargo run -- web --once
cargo run -- web --interface "Ethernet" --interval 5
```

`web` does not read browser history or server logs. It captures packets from the
network interface and parses protocol metadata. On Linux this uses raw sockets
and usually requires root or `CAP_NET_RAW`. On Windows this uses
[Npcap](https://npcap.com/) which must be installed separately.

Intervals must be positive and representable with nanosecond precision.
Press Ctrl+C to interrupt monitoring waits; packet capture checks for shutdown
between packet reads (normally within the 200 ms capture timeout).

All three subcommands stream output, so they can be piped. Closing the pipe
early, for example with `head`, ends the process quietly rather than raising an
error.

## Limits

The operating system connection table usually exposes remote IP addresses and
ports, not the original website name. HTTPS, HTTP/2 multiplexing, CDNs, proxies,
and DNS privacy can prevent reliable domain-level attribution.

For example, OpenAI traffic may appear as one or more `IP:443` connections
rather than `openai.com`.

The `web` command can recover domains only when they appear in DNS queries or
TLS SNI. It will not see domains hidden by encrypted DNS, encrypted ClientHello,
VPN tunnels, proxies, or already-established connections that began before
capture started.

`web` parses each packet as it arrives and does not reassemble TCP streams. A
TLS ClientHello larger than the path MTU is split across segments, and the SNI
is then missing from every individual segment, so large ClientHellos are not
always attributed. The same applies to a DNS query split across TCP segments,
which is uncommon since queries are small.

## Build

```bash
cargo build --release
```

On Windows, building with the default `npcap` feature requires the
[Npcap SDK](https://npcap.com/#download). Extract it and add the `Lib/x64`
directory to your `LIB` environment variable. To build without Npcap support:

```bash
cargo build --release --no-default-features
```

The release binary is written to `target/release/netor`.
