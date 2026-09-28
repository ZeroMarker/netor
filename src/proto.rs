//! Pure packet dissection: turns a raw link-layer frame into domain events.
//!
//! Everything in this module is a pure function over byte slices so that it
//! can be tested without a capture handle, and so that malformed or truncated
//! packets can never panic or read out of bounds.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebEvent {
    pub source: &'static str,
    pub domain: String,
}

const PROTO_HOPOPTS: u8 = 0;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ROUTING: u8 = 43;
const PROTO_FRAGMENT: u8 = 44;
const PROTO_AH: u8 = 51;
const PROTO_DSTOPTS: u8 = 60;
const PROTO_MOBILITY: u8 = 135;

const MAX_IPV6_EXTENSION_HEADERS: usize = 8;

const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

const DNS_PORT: u16 = 53;
const TLS_PORT: u16 = 443;

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;

pub fn parse_packet_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    let Some(ip_packet) = ethernet_payload(packet) else {
        return Vec::new();
    };

    parse_ip_payload_for_web_events(ip_packet)
}

pub fn ethernet_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < ETH_HEADER_LEN {
        return None;
    }

    let mut ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    let mut offset = ETH_HEADER_LEN;

    // Peel off up to two levels of VLAN tags.
    while matches!(ethertype, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        let next = packet.get(offset + 2..offset + 4)?;
        ethertype = u16::from_be_bytes([next[0], next[1]]);
        offset += 4;
    }

    match ethertype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => packet.get(offset..),
        _ => None,
    }
}

pub fn parse_ip_payload_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.is_empty() {
        return Vec::new();
    }

    match packet[0] >> 4 {
        4 => parse_ipv4_for_web_events(packet),
        6 => parse_ipv6_for_web_events(packet),
        _ => Vec::new(),
    }
}

pub fn parse_ipv4_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < IPV4_MIN_HEADER {
        return Vec::new();
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER || packet.len() < header_len {
        return Vec::new();
    }

    match packet[9] {
        PROTO_TCP => parse_tcp_for_web_events(&packet[header_len..]),
        PROTO_UDP => parse_udp_for_web_events(&packet[header_len..]),
        _ => Vec::new(),
    }
}

pub fn parse_ipv6_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < IPV6_HEADER_LEN {
        return Vec::new();
    }

    let mut next_header = packet[6];
    let mut offset = IPV6_HEADER_LEN;

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

pub fn parse_udp_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < UDP_HEADER_LEN {
        return Vec::new();
    }

    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
    if source_port != DNS_PORT && destination_port != DNS_PORT {
        return Vec::new();
    }

    // Clamp to the declared UDP length so that Ethernet padding is never
    // mistaken for DNS data.
    let declared = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let end = declared.clamp(UDP_HEADER_LEN, packet.len());

    parse_dns_query_domains(&packet[UDP_HEADER_LEN..end])
        .into_iter()
        .map(|domain| WebEvent {
            source: "dns",
            domain,
        })
        .collect()
}

pub fn parse_tcp_for_web_events(packet: &[u8]) -> Vec<WebEvent> {
    if packet.len() < TCP_MIN_HEADER {
        return Vec::new();
    }

    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
    let header_len = usize::from(packet[12] >> 4) * 4;
    if header_len < TCP_MIN_HEADER || packet.len() < header_len {
        return Vec::new();
    }

    let payload = &packet[header_len..];
    let mut events = Vec::new();

    if (source_port == DNS_PORT || destination_port == DNS_PORT) && payload.len() >= 2 {
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

    if source_port == TLS_PORT || destination_port == TLS_PORT {
        if let Some(domain) = parse_tls_sni(payload) {
            events.push(WebEvent {
                source: "tls-sni",
                domain,
            });
        }
    }

    events
}

pub fn parse_dns_query_domains(packet: &[u8]) -> Vec<String> {
    if packet.len() < DNS_HEADER_LEN {
        return Vec::new();
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_response = flags & 0x8000 != 0;
    if is_response {
        return Vec::new();
    }

    let question_count = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let mut offset = DNS_HEADER_LEN;
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

pub fn parse_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
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

pub fn parse_tls_sni(packet: &[u8]) -> Option<String> {
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

pub fn parse_tls_sni_extension(extension: &[u8]) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but well-formed TLS ClientHello carrying `domain` as SNI.
    fn client_hello(domain: &str) -> Vec<u8> {
        let mut body = vec![0x03, 0x03]; // client version TLS 1.2
        body.extend_from_slice(&[0x00; 32]); // random
        body.push(0x00); // empty session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.push(0x01); // one compression method
        body.push(0x00); // null compression

        let mut names = vec![0x00]; // host_name
        names.extend_from_slice(&(domain.len() as u16).to_be_bytes());
        names.extend_from_slice(domain.as_bytes());

        // A ServerNameList is a 2-byte total length followed directly by the
        // name entries, with no further wrapping length.
        let mut extension = Vec::new();
        extension.extend_from_slice(&(names.len() as u16).to_be_bytes());
        extension.extend_from_slice(&names);

        let mut extensions = vec![0x00, 0x00]; // server_name extension type
        extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&extension);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01]; // ClientHello
        let body_len = body.len();
        handshake.push((body_len >> 16) as u8);
        handshake.push((body_len >> 8) as u8);
        handshake.push(body_len as u8);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Builds a bare TCP segment with no payload options.
    fn tcp_segment(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&source_port.to_be_bytes());
        tcp.extend_from_slice(&destination_port.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]); // sequence
        tcp.extend_from_slice(&[0, 0, 0, 0]); // acknowledgement
        tcp.push(0x50); // data offset 5 words
        tcp.push(0x18); // PSH | ACK
        tcp.extend_from_slice(&[0xFF, 0xFF]); // window
        tcp.extend_from_slice(&[0, 0]); // checksum
        tcp.extend_from_slice(&[0, 0]); // urgent pointer
        tcp.extend_from_slice(payload);
        assert_eq!(tcp.len(), TCP_MIN_HEADER + payload.len());
        tcp
    }

    /// Wraps a TCP segment in an Ethernet + IPv4 envelope.
    fn tcp_over_ipv4(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let tcp = tcp_segment(source_port, destination_port, payload);

        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&((IPV4_MIN_HEADER + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]); // identification
        ip.extend_from_slice(&[0, 0]); // flags and fragment offset
        ip.push(64); // ttl
        ip.push(PROTO_TCP);
        ip.extend_from_slice(&[0, 0]); // checksum
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[93, 184, 216, 34]);
        ip.extend_from_slice(&tcp);
        assert_eq!(ip.len(), IPV4_MIN_HEADER + tcp.len());

        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    /// Wraps a UDP datagram in an Ethernet + IPv4 envelope.
    fn udp_over_ipv4(datagram: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&((20 + datagram.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, PROTO_UDP, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8]);

        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(datagram);
        frame
    }

    /// Builds a UDP datagram carrying `domains`, but declares a UDP length that
    /// covers only the first `covered_questions` of them.
    ///
    /// Anything past the declared length is what a NIC would have padded the
    /// frame with, and a parser that ignores the length field will read it as
    /// further questions.
    fn udp_dns(domains: &[&str], covered_questions: usize) -> Vec<u8> {
        let mut dns = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        dns[4..6].copy_from_slice(&(domains.len() as u16).to_be_bytes());

        let mut covered_len = DNS_HEADER_LEN;
        for (index, domain) in domains.iter().enumerate() {
            for label in domain.split('.') {
                dns.push(label.len() as u8);
                dns.extend_from_slice(label.as_bytes());
            }
            dns.push(0x00);
            dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            if index + 1 == covered_questions {
                covered_len = dns.len();
            }
        }

        let mut udp = Vec::new();
        udp.extend_from_slice(&DNS_PORT.to_be_bytes());
        udp.extend_from_slice(&40000u16.to_be_bytes());
        udp.extend_from_slice(&((UDP_HEADER_LEN + covered_len) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum
        udp.extend_from_slice(&dns);
        udp
    }

    fn dns_domains(events: &[WebEvent]) -> Vec<String> {
        events
            .iter()
            .filter(|event| event.source == "dns")
            .map(|event| event.domain.clone())
            .collect()
    }

    #[test]
    fn extracts_tls_sni_end_to_end() {
        let frame = tcp_over_ipv4(51000, TLS_PORT, &client_hello("www.example.com"));
        let events = parse_packet_for_web_events(&frame);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "tls-sni");
        assert_eq!(events[0].domain, "www.example.com");
    }

    #[test]
    fn extracts_dns_from_udp_end_to_end() {
        let frame = udp_over_ipv4(&udp_dns(&["example.com"], 1));
        let events = parse_packet_for_web_events(&frame);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "dns");
        assert_eq!(events[0].domain, "example.com");
    }

    #[test]
    fn ignores_dns_beyond_the_declared_udp_length() {
        // Two questions are on the wire but the datagram only declares the
        // first, so the second must not be reported.
        let frame = udp_over_ipv4(&udp_dns(&["example.com", "hidden.in.padding"], 1));
        assert_eq!(
            dns_domains(&parse_packet_for_web_events(&frame)),
            ["example.com"]
        );
    }

    #[test]
    fn parses_dns_past_a_short_declared_udp_length_only_when_declared() {
        // The complement of the test above: declaring both questions yields both.
        let frame = udp_over_ipv4(&udp_dns(&["example.com", "second.example.com"], 2));
        assert_eq!(
            dns_domains(&parse_packet_for_web_events(&frame)),
            ["example.com", "second.example.com"]
        );
    }

    #[test]
    fn rejects_zero_and_oversized_udp_lengths() {
        for declared in [0u16, 4, 0xFFFF] {
            let mut datagram = udp_dns(&["example.com"], 1);
            datagram[4..6].copy_from_slice(&declared.to_be_bytes());
            let events = parse_udp_for_web_events(&datagram);
            // A declared length below the header clamps to the header, and an
            // oversized one clamps to the buffer; neither may panic.
            assert!(events.len() <= 1, "declared {declared}");
        }
    }

    #[test]
    fn peels_qinq_vlan_tags() {
        let mut packet = vec![0u8; 42];
        packet[12] = 0x88;
        packet[13] = 0xa8; // outer 802.1ad
        packet[14] = 0x00;
        packet[15] = 0x0c; // VLAN id
        packet[16] = 0x81;
        packet[17] = 0x00; // inner 802.1Q
        packet[18] = 0x00;
        packet[19] = 0x14; // VLAN id
        packet[20] = 0x08;
        packet[21] = 0x00; // IPv4
        packet[22] = 0x45; // IPv4 version/IHL
        assert_eq!(ethernet_payload(&packet).map(<[u8]>::len), Some(42 - 22));
    }

    #[test]
    fn rejects_truncated_vlan_tag() {
        let mut packet = vec![0u8; 15];
        packet[12] = 0x81;
        packet[13] = 0x00;
        assert_eq!(ethernet_payload(&packet), None);
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
    fn skips_ipv6_extension_headers() {
        // IPv6 header, an 8 byte hop-by-hop header, then a TCP segment
        // carrying a full TLS ClientHello.
        let tcp = tcp_segment(51000, TLS_PORT, &client_hello("ipv6.example.com"));
        let mut packet = vec![0u8; 40 + 8];
        packet[0] = 0x60;
        packet[6] = PROTO_HOPOPTS;
        packet[40] = PROTO_TCP; // hop-by-hop points at TCP
        packet[41] = 0; // 8 byte hop-by-hop header
        packet.extend_from_slice(&tcp);

        let events = parse_ipv6_for_web_events(&packet);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].domain, "ipv6.example.com");
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
            packet[40] = PROTO_TCP;
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
        // A chain of hop-by-hop headers must terminate rather than spin.
        let mut packet = vec![0u8; 40 + 8 * 64];
        packet[6] = PROTO_HOPOPTS;
        for index in 0..64 {
            packet[40 + index * 8] = PROTO_HOPOPTS;
        }
        assert!(parse_ipv6_for_web_events(&packet).is_empty());
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
    fn parses_dns_query_domains() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        assert_eq!(parse_dns_query_domains(&packet), vec!["example.com"]);
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
    fn parses_dns_short_packet_returns_empty() {
        assert_eq!(parse_dns_query_domains(&[0u8; 5]), Vec::<String>::new());
    }

    #[test]
    fn lowercases_dns_names() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'W',
            b'W', b'W', 0x03, b'C', b'O', b'M', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(parse_dns_query_domains(&packet), vec!["www.com"]);
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

    #[test]
    fn rejects_dns_name_pointers_that_loop() {
        // A pointer that targets itself must terminate instead of hanging.
        assert_eq!(parse_dns_name(&[0xC0, 0x00], 0), None);
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
    fn rejects_short_tls_sni_extension() {
        assert_eq!(parse_tls_sni_extension(&[0x00]), None);
        assert_eq!(parse_tls_sni_extension(&[]), None);
    }

    #[test]
    fn rejects_tls_sni_extension_with_bad_list_length() {
        assert_eq!(parse_tls_sni_extension(&[0xFF, 0xFF]), None);
    }

    #[test]
    fn rejects_non_tls_packets() {
        assert_eq!(parse_tls_sni(&[0u8; 5]), None);
        assert_eq!(parse_tls_sni(&[22, 3, 1, 0, 5, 99]), None);
    }

    #[test]
    fn rejects_tls_record_longer_than_the_segment() {
        // A ClientHello split across TCP segments cannot be parsed; this
        // documents the current no-reassembly behaviour.
        let mut hello = client_hello("split.example.com");
        hello.truncate(20);
        assert_eq!(parse_tls_sni(&hello), None);
    }

    #[test]
    fn reads_three_byte_lengths() {
        assert_eq!(read_u24(&[0x00, 0x10, 0x00]), Some(4096));
        assert_eq!(read_u24(&[0x10, 0x00]), None);
    }

    #[test]
    fn every_truncation_of_a_client_hello_is_safe() {
        // A fuzz-style guard: no prefix of a real ClientHello may panic.
        let hello = client_hello("truncate.example.com");
        for length in 0..hello.len() {
            let _ = parse_tls_sni(&hello[..length]);
            let _ = parse_tcp_for_web_events(&hello[..length]);
        }
    }

    #[test]
    fn every_truncation_of_a_dns_query_is_safe() {
        let query = udp_dns(&["truncate.example.com"], 1);
        for length in 0..query.len() {
            let _ = parse_udp_for_web_events(&query[..length]);
        }
    }
}
