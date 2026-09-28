//! The kernel-side capture filter.
//!
//! Without a filter, `netor` receives and dissects every frame on the wire.
//! The program below is a classic BPF filter installed with `SO_ATTACH_FILTER`
//! (Linux) or compiled from an equivalent expression (Windows), so the kernel
//! can discard traffic that `netor` would only throw away anyway.
//!
//! This is deliberately a *load* filter and not a correctness filter. The
//! dissector in `proto` remains the authority, so the program errs towards
//! letting a packet through:
//!
//! - ARP, other non-IP frames and IP traffic on other ports are rejected.
//! - IPv4 is matched using the real header length, so IP options work.
//! - IPv6 is matched only when the next header is directly TCP or UDP. The
//!   extension headers the dissector walks are accepted explicitly, so nothing
//!   behind one is lost.
//! - VLAN and QinQ tagged frames are always accepted, since they are still IP
//!   traffic the dissector understands.
//!
//! Classic BPF jumps are forward only, so both `RET` instructions sit at the
//! end: index [`REJECT_INDEX`] returns zero bytes and [`ACCEPT_INDEX`] returns
//! the full snaplen. `run_bpf` below is a reference interpreter for this
//! instruction set, so the program is tested against real frames rather than
//! trusted.

use crate::capture::FilterInstruction;

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;

const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

/// Jump opcodes understood by the reference interpreter.
#[cfg(test)]
const BPF_JSET: u16 = 0x40;

/// Accept: return the full snaplen.
const ACCEPT: u32 = 0xFFFF_FFFF;
/// Reject: return zero bytes.
const REJECT: u32 = 0;

const ETHERTYPE_IPV4: u32 = 0x0800;
const ETHERTYPE_IPV6: u32 = 0x86dd;
const ETHERTYPE_VLAN: u32 = 0x8100;
const ETHERTYPE_QINQ: u32 = 0x88a8;

const PROTO_HOPOPTS: u32 = 0;
const PROTO_TCP: u32 = 6;
const PROTO_UDP: u32 = 17;
const PROTO_ROUTING: u32 = 43;
const PROTO_FRAGMENT: u32 = 44;
const PROTO_AH: u32 = 51;
const PROTO_DSTOPTS: u32 = 60;
const PROTO_MOBILITY: u32 = 135;

const DNS_PORT: u32 = 53;
const TLS_PORT: u32 = 443;

const OFFSET_ETHERTYPE: u32 = 12;
const OFFSET_IPV4_PROTOCOL: u32 = 23;
const OFFSET_IPV4_IHL: u32 = 14;
const OFFSET_IPV6_NEXT_HEADER: u32 = 20;
/// 14 byte Ethernet header plus a 40 byte IPv6 header, used as X.
const IPV6_PAYLOAD_X: u32 = 40;
/// `X` is the IP header length for IPv4 and 40 for IPv6, so adding this lands
/// on the transport source port in both cases.
const PORT_SOURCE_OFFSET: u32 = 14;
const PORT_DEST_OFFSET: u32 = 16;

/// Index of the instruction that rejects.
#[cfg(test)]
const REJECT_INDEX: usize = 31;
/// Index of the instruction that accepts.
#[cfg(test)]
const ACCEPT_INDEX: usize = 32;

/// The equivalent tcpdump expression for [`INTEREST_FILTER`], used where a
/// filter is compiled from a string rather than installed as instructions.
#[cfg(all(windows, feature = "npcap"))]
pub const PCAP_FILTER: &str = "(tcp or udp) and (port 53 or port 443)";

/// Classic BPF program: TCP or UDP with port 53 or 443 on IPv4 or IPv6.
pub const INTEREST_FILTER: &[FilterInstruction] = &[
    // 0: ethertype
    FilterInstruction {
        code: BPF_LD | BPF_H | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_ETHERTYPE,
    },
    // 1: IPv4? -> 3
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: ETHERTYPE_IPV4,
    },
    // 2: IPv6? -> 13, else 29
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 10,
        jf: 26,
        k: ETHERTYPE_IPV6,
    },
    // 3: IPv4 protocol
    FilterInstruction {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_IPV4_PROTOCOL,
    },
    // 4: TCP? -> 6
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: PROTO_TCP,
    },
    // 5: UDP? -> 6, else reject
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 25,
        k: PROTO_UDP,
    },
    // 6: X = IP header length
    FilterInstruction {
        code: BPF_LDX | BPF_B | BPF_MSH,
        jt: 0,
        jf: 0,
        k: OFFSET_IPV4_IHL,
    },
    // 7: IPv4 source port
    FilterInstruction {
        code: BPF_LD | BPF_H | BPF_IND,
        jt: 0,
        jf: 0,
        k: PORT_SOURCE_OFFSET,
    },
    // 8: source port 53 -> accept
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 23,
        jf: 0,
        k: DNS_PORT,
    },
    // 9: source port 443 -> accept
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 22,
        jf: 0,
        k: TLS_PORT,
    },
    // 10: IPv4 destination port
    FilterInstruction {
        code: BPF_LD | BPF_H | BPF_IND,
        jt: 0,
        jf: 0,
        k: PORT_DEST_OFFSET,
    },
    // 11: destination port 53 -> accept
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 20,
        jf: 0,
        k: DNS_PORT,
    },
    // 12: destination port 443 -> accept, else reject
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 19,
        jf: 18,
        k: TLS_PORT,
    },
    // 13: IPv6 next header
    FilterInstruction {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_IPV6_NEXT_HEADER,
    },
    // 14: TCP? -> 16
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: PROTO_TCP,
    },
    // 15: UDP? -> 16, else 23
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 7,
        k: PROTO_UDP,
    },
    // 16: X = IPv6 header length
    FilterInstruction {
        code: BPF_LDX | BPF_W | BPF_IMM,
        jt: 0,
        jf: 0,
        k: IPV6_PAYLOAD_X,
    },
    // 17: IPv6 source port
    FilterInstruction {
        code: BPF_LD | BPF_H | BPF_IND,
        jt: 0,
        jf: 0,
        k: PORT_SOURCE_OFFSET,
    },
    // 18: source port 53 -> accept
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 13,
        jf: 0,
        k: DNS_PORT,
    },
    // 19: source port 443 -> accept
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 12,
        jf: 0,
        k: TLS_PORT,
    },
    // 20: IPv6 destination port
    FilterInstruction {
        code: BPF_LD | BPF_H | BPF_IND,
        jt: 0,
        jf: 0,
        k: PORT_DEST_OFFSET,
    },
    // 21: destination port 53 -> accept
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 10,
        jf: 0,
        k: DNS_PORT,
    },
    // 22: destination port 443 -> accept, else reject
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 9,
        jf: 8,
        k: TLS_PORT,
    },
    // 23..28: IPv6 extension headers the dissector resolves itself. A match
    // accepts so that nothing behind an extension header is lost; anything
    // else falls through to the next check and ends at the reject.
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 8,
        jf: 0,
        k: PROTO_HOPOPTS,
    },
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 7,
        jf: 0,
        k: PROTO_ROUTING,
    },
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 6,
        jf: 0,
        k: PROTO_FRAGMENT,
    },
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 5,
        jf: 0,
        k: PROTO_AH,
    },
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 4,
        jf: 0,
        k: PROTO_DSTOPTS,
    },
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 3,
        jf: 2,
        k: PROTO_MOBILITY,
    },
    // 29: VLAN? -> accept
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 2,
        jf: 0,
        k: ETHERTYPE_VLAN,
    },
    // 30: QinQ? -> accept, else reject
    FilterInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: ETHERTYPE_QINQ,
    },
    // 31: reject
    FilterInstruction {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: REJECT,
    },
    // 32: accept
    FilterInstruction {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: ACCEPT,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference interpreter for the classic BPF subset used above.
    ///
    /// Out of range loads return zero, matching the kernel, so a short packet
    /// can never read past the end of the buffer.
    fn run_bpf(program: &[FilterInstruction], packet: &[u8]) -> u32 {
        fn load(packet: &[u8], offset: usize, width: usize) -> u32 {
            match packet.get(offset..offset + width) {
                Some(slice) if width == 4 => {
                    u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
                }
                Some(slice) if width == 2 => u32::from(u16::from_be_bytes([slice[0], slice[1]])),
                Some(slice) => u32::from(slice[0]),
                None => 0,
            }
        }

        let mut accumulator: u32 = 0;
        let mut index: u32 = 0;
        let mut pc = 0_usize;

        for _ in 0..=program.len() {
            let instruction = &program[pc];
            let class = instruction.code & 0x07;

            match class {
                BPF_LD => {
                    let offset = match instruction.code & 0xe0 {
                        BPF_ABS => instruction.k as usize,
                        BPF_IND => (index + instruction.k) as usize,
                        _ => panic!("unsupported load mode {:#x}", instruction.code),
                    };
                    accumulator = load(
                        packet,
                        offset,
                        match instruction.code & 0x18 {
                            BPF_W => 4,
                            BPF_H => 2,
                            _ => 1,
                        },
                    );
                    pc += 1;
                }
                BPF_LDX => {
                    if instruction.code & BPF_MSH == BPF_MSH {
                        // 4 * (IHL & 0xf)
                        index = 4 * (load(packet, instruction.k as usize, 1) & 0x0f);
                    } else if instruction.code & 0x18 == BPF_W {
                        index = instruction.k;
                    } else {
                        panic!("unsupported ldx {:#x}", instruction.code);
                    }
                    pc += 1;
                }
                BPF_JMP => match instruction.code & 0xf0 {
                    BPF_JEQ | BPF_JSET => {
                        let taken = if instruction.code & 0xf0 == BPF_JEQ {
                            accumulator == instruction.k
                        } else {
                            accumulator & instruction.k != 0
                        };
                        let offset = if taken {
                            usize::from(instruction.jt)
                        } else {
                            usize::from(instruction.jf)
                        };
                        pc += 1 + offset;
                    }
                    other => panic!("unsupported jump {other:#x}"),
                },
                BPF_RET => return instruction.k,
                other => panic!("unsupported instruction class {other:#x}"),
            }
        }

        panic!("filter ran off the end without a return");
    }

    fn ipv4(protocol: u8, ihl_words: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
        // Version 4 in the high nibble, the header length in the low one.
        let mut ip = vec![0x40 | (ihl_words & 0x0f), 0x00];
        ip.extend_from_slice(&[0, 0]); // total length
        ip.extend_from_slice(&[0, 0, 0, 0]); // id, flags
        ip.push(64); // ttl
        ip.push(protocol);
        ip.extend_from_slice(&[0, 0]); // checksum
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[93, 184, 216, 34]);
        while ip.len() < usize::from(ihl_words) * 4 {
            // IP options
            ip.push(0);
        }
        ip.extend_from_slice(&source_port.to_be_bytes());
        ip.extend_from_slice(&destination_port.to_be_bytes());
        ip.extend_from_slice(&[0; 8]); // seq, ack
        ip.push(0x50);
        ip.extend_from_slice(&[0, 0, 0, 0]);

        let mut frame = vec![0_u8; 12];
        frame.extend_from_slice(&(ETHERTYPE_IPV4 as u16).to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    fn ipv6(next_header: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&[0, 8]); // payload length
        ip.push(next_header);
        ip.push(64); // hop limit
        ip.extend_from_slice(&[0; 16]); // source
        ip.extend_from_slice(&[0; 16]); // destination
        ip.extend_from_slice(&source_port.to_be_bytes());
        ip.extend_from_slice(&destination_port.to_be_bytes());
        ip.extend_from_slice(&[0; 8]); // seq, ack
        ip.push(0x50);
        ip.extend_from_slice(&[0, 0, 0, 0]);

        let mut frame = vec![0_u8; 12];
        frame.extend_from_slice(&(ETHERTYPE_IPV6 as u16).to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    /// Wraps a frame in a single 802.1Q tag, so the inner ethertype moves
    /// behind the tag.
    fn with_vlan(frame: &[u8]) -> Vec<u8> {
        let mut tagged = frame[..12].to_vec();
        tagged.extend_from_slice(&(ETHERTYPE_VLAN as u16).to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x0C]); // priority and VLAN id
        tagged.extend_from_slice(&frame[12..]);
        tagged
    }

    fn accepts(frame: &[u8]) -> bool {
        run_bpf(INTEREST_FILTER, frame) == ACCEPT
    }

    #[test]
    fn accepts_dns_and_tls_ports_on_ipv4() {
        for protocol in [6_u8, 17] {
            assert!(accepts(&ipv4(protocol, 5, 40_000, 53)), "dst 53/{protocol}");
            assert!(accepts(&ipv4(protocol, 5, 53, 40_000)), "src 53/{protocol}");
            assert!(
                accepts(&ipv4(protocol, 5, 40_000, 443)),
                "dst 443/{protocol}"
            );
            assert!(
                accepts(&ipv4(protocol, 5, 443, 40_000)),
                "src 443/{protocol}"
            );
        }
    }

    #[test]
    fn rejects_other_ports_on_ipv4() {
        for protocol in [6_u8, 17] {
            assert!(
                !accepts(&ipv4(protocol, 5, 40_000, 80)),
                "dst 80/{protocol}"
            );
            assert!(
                !accepts(&ipv4(protocol, 5, 80, 40_000)),
                "src 80/{protocol}"
            );
            assert!(!accepts(&ipv4(protocol, 5, 1234, 5678)), "other/{protocol}");
        }
    }

    #[test]
    fn handles_ipv4_ip_options() {
        // IHL 6 means a 24 byte header, so the ports sit 4 bytes later.
        assert!(accepts(&ipv4(6, 6, 40_000, 443)));
        assert!(!accepts(&ipv4(6, 6, 40_000, 80)));
    }

    #[test]
    fn accepts_dns_and_tls_ports_on_ipv6() {
        for next_header in [6_u8, 17] {
            assert!(
                accepts(&ipv6(next_header, 40_000, 53)),
                "dst 53/{next_header}"
            );
            assert!(
                accepts(&ipv6(next_header, 443, 40_000)),
                "src 443/{next_header}"
            );
            assert!(
                !accepts(&ipv6(next_header, 40_000, 80)),
                "dst 80/{next_header}"
            );
        }
    }

    #[test]
    fn lets_ipv6_extension_headers_through() {
        // These are all resolved by the dissector, so the filter must not
        // discard them.
        for next_header in [
            PROTO_HOPOPTS,
            PROTO_ROUTING,
            PROTO_FRAGMENT,
            PROTO_AH,
            PROTO_DSTOPTS,
            PROTO_MOBILITY,
        ] {
            assert!(
                accepts(&ipv6(next_header as u8, 40_000, 9999)),
                "{next_header}"
            );
        }
    }

    #[test]
    fn rejects_other_ipv6_protocols() {
        // ICMPv6, ESP, no-next-header and unknown protocols carry no DNS or
        // TLS that the dissector could reach.
        for next_header in [17_u8, 41, 50, 58, 59, 132, 255] {
            if matches!(next_header, 6 | 17) {
                continue;
            }
            assert!(!accepts(&ipv6(next_header, 0, 0)), "{next_header}");
        }
    }

    #[test]
    fn rejects_non_tcp_udp_ipv4() {
        for protocol in [1_u8, 2, 47, 50, 89, 255] {
            assert!(!accepts(&ipv4(protocol, 5, 40_000, 443)), "{protocol}");
        }
    }

    #[test]
    fn rejects_arp_and_other_ethertypes() {
        let mut arp = vec![0_u8; 60];
        arp[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        assert!(!accepts(&arp));

        let mut llc = vec![0_u8; 60];
        llc[12..14].copy_from_slice(&0x0006_u16.to_be_bytes());
        assert!(!accepts(&llc));
    }

    #[test]
    fn lets_vlan_tagged_traffic_through() {
        assert!(accepts(&with_vlan(&ipv4(6, 5, 40_000, 9999))));
        assert!(accepts(&with_vlan(&ipv6(6, 40_000, 9999))));
    }

    #[test]
    fn truncated_packets_never_panic() {
        let frame = ipv4(6, 5, 40_000, 443);
        for length in 0..frame.len() {
            let _ = accepts(&frame[..length]);
        }
        let frame = ipv6(17, 40_000, 53);
        for length in 0..frame.len() {
            let _ = accepts(&frame[..length]);
        }
    }

    #[test]
    fn opcodes_match_the_kernel_abi() {
        // These are the values from uapi/linux/bpf_common.h. The reference
        // interpreter below uses the same constants, so a wrong constant here
        // would be invisible to the frame tests but rejected by the kernel
        // with EINVAL. Pinning the encodings catches that.
        assert_eq!(BPF_LD, 0x00);
        assert_eq!(BPF_LDX, 0x01);
        assert_eq!(BPF_JMP, 0x05);
        assert_eq!(BPF_RET, 0x06);
        assert_eq!(BPF_W, 0x00);
        assert_eq!(BPF_H, 0x08);
        assert_eq!(BPF_B, 0x10);
        assert_eq!(BPF_IMM, 0x00);
        assert_eq!(BPF_ABS, 0x20);
        assert_eq!(BPF_IND, 0x40);
        assert_eq!(BPF_MSH, 0xa0);
        assert_eq!(BPF_JEQ, 0x10);
        assert_eq!(BPF_JSET, 0x40);
        assert_eq!(BPF_K, 0x00);

        // The encodings the program actually uses.
        assert_eq!(BPF_LD | BPF_H | BPF_ABS, 0x28);
        assert_eq!(BPF_LD | BPF_B | BPF_ABS, 0x30);
        assert_eq!(BPF_LD | BPF_H | BPF_IND, 0x48);
        assert_eq!(BPF_LDX | BPF_B | BPF_MSH, 0xb1);
        assert_eq!(BPF_LDX | BPF_W | BPF_IMM, 0x01);
        assert_eq!(BPF_JMP | BPF_JEQ | BPF_K, 0x15);
        assert_eq!(BPF_RET | BPF_K, 0x06);
    }

    #[test]
    fn program_is_well_formed() {
        let program = INTEREST_FILTER;
        assert_eq!(program.len(), ACCEPT_INDEX + 1);
        assert_eq!(program.len(), REJECT_INDEX + 2);
        assert!(program.len() <= usize::from(u16::MAX));

        for (index, instruction) in program.iter().enumerate() {
            if instruction.code & 0x07 != BPF_JMP {
                continue;
            }
            for offset in [instruction.jt, instruction.jf] {
                let target = index + 1 + usize::from(offset);
                assert!(
                    target < program.len(),
                    "jump from {index} leaves the program at {target}"
                );
            }
        }

        assert_eq!(program[REJECT_INDEX].k, REJECT);
        assert_eq!(program[ACCEPT_INDEX].k, ACCEPT);
        assert_eq!(program[REJECT_INDEX].code & 0x07, BPF_RET);
        assert_eq!(program[ACCEPT_INDEX].code & 0x07, BPF_RET);
    }
}
