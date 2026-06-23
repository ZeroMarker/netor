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
- Real-time DNS and TLS SNI domain capture on Linux raw sockets
- Receive/transmit rates and totals per network interface
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
sudo cargo run -- web --once
sudo cargo run -- web --interface eth0 --interval 5
```

`web` does not read browser history or server logs. It captures packets from the
network interface and parses protocol metadata. On Linux this uses raw sockets
and usually requires root or `CAP_NET_RAW`.

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

## Build

```bash
cargo build --release
```

The release binary is written to `target/release/netor`.
