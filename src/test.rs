// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{Emitable, ParseableParametrized};
use netlink_packet_generic::{GenlFamily, GenlHeader};
use pretty_assertions::assert_eq;

use crate::{FouAddressFamily, FouAttribute, FouCmd, FouEncap, FouMessage};

/// Parse `raw` (generic netlink header followed by attributes) and check
/// that emitting the parsed message reproduces `raw` byte for byte.
fn assert_parse_and_emit(raw: &[u8], expected: &FouMessage) {
    let header = GenlHeader::parse(raw).unwrap();
    assert_eq!(
        &FouMessage::parse_with_param(&raw[4..], header).unwrap(),
        expected
    );

    let mut buffer = vec![0; expected.buffer_len() + 4];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

// nlmon capture of the kernel reply to `sudo ip fou show` in a network
// namespace holding a IPv4 GUE listener, a IPv6 direct listener and a IPv4
// GUE listener with `FOU_ATTR_REMCSUM_NOPARTIAL` set. Only the netlink
// header of each message is purged, the generic netlink header is kept as
// the first 4 bytes below.
//
// The kernel does not mark `FOU_ATTR_PORT` and `FOU_ATTR_PEER_PORT` with
// `NLA_F_NET_BYTEORDER` (`nla_put_be16()` does not add the flag), therefore
// the attribute types are plain `0x0001` and `0x000a`.

// IPv6 listener created by
// `ip -6 fou add port 1001 ipproto 17 local 2001:db8::1 -6`.
// Generic netlink `FOU_CMD_GET` reply with AF, PORT, PEER_PORT, IPPROTO,
// TYPE, IFINDEX, LOCAL_V6 and PEER_V6.
#[test]
fn test_parse_kernel_reply_ipv6() {
    let raw: Vec<u8> = vec![
        0x03, 0x01, 0x00, 0x00, // genlmsghdr: FOU_CMD_GET, version 1
        0x05, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, // af inet6
        0x06, 0x00, 0x01, 0x00, 0x03, 0xe9, 0x00, 0x00, // port 1001
        0x06, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, // peer port 0
        0x05, 0x00, 0x03, 0x00, 0x11, 0x00, 0x00, 0x00, // ipproto udp
        0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // direct
        0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, // ifindex 0
        0x14, 0x00, 0x07, 0x00, 0x20, 0x01, 0x0d,
        0xb8, // local 2001:db8::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x14, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // peer ::
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &FouMessage {
            cmd: FouCmd::Get,
            attributes: vec![
                FouAttribute::Family(FouAddressFamily::Ipv6),
                FouAttribute::Port(1001),
                FouAttribute::PeerPort(0),
                FouAttribute::Ipproto(17),
                FouAttribute::Encap(FouEncap::Direct),
                FouAttribute::IfIndex(0),
                FouAttribute::LocalV6(
                    "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                ),
                FouAttribute::PeerV6(Ipv6Addr::UNSPECIFIED),
            ],
        },
    );
}

// IPv4 listener created by `ip fou add port 1000 gue local 10.9.9.1
// peer 10.9.9.2 peer_port 2000 dev foudev0`.
// Generic netlink `FOU_CMD_GET` reply with AF, PORT, PEER_PORT, IPPROTO,
// TYPE, IFINDEX, LOCAL_V4 and PEER_V4.
#[test]
fn test_parse_kernel_reply_ipv4_gue() {
    let raw: Vec<u8> = vec![
        0x03, 0x01, 0x00, 0x00, // genlmsghdr: FOU_CMD_GET, version 1
        0x05, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, // af inet
        0x06, 0x00, 0x01, 0x00, 0x03, 0xe8, 0x00, 0x00, // port 1000
        0x06, 0x00, 0x0a, 0x00, 0x07, 0xd0, 0x00, 0x00, // peer port 2000
        0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // ipproto 0
        0x05, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, // gue
        0x08, 0x00, 0x0b, 0x00, 0x0b, 0x00, 0x00, 0x00, // ifindex 11
        0x08, 0x00, 0x06, 0x00, 0x0a, 0x09, 0x09, 0x01, // local 10.9.9.1
        0x08, 0x00, 0x08, 0x00, 0x0a, 0x09, 0x09, 0x02, // peer 10.9.9.2
    ];

    assert_parse_and_emit(
        &raw,
        &FouMessage {
            cmd: FouCmd::Get,
            attributes: vec![
                FouAttribute::Family(FouAddressFamily::Ipv4),
                FouAttribute::Port(1000),
                FouAttribute::PeerPort(2000),
                FouAttribute::Ipproto(0),
                FouAttribute::Encap(FouEncap::Gue),
                FouAttribute::IfIndex(11),
                FouAttribute::LocalV4(Ipv4Addr::new(10, 9, 9, 1)),
                FouAttribute::PeerV4(Ipv4Addr::new(10, 9, 9, 2)),
            ],
        },
    );
}

// IPv4 listener with `FOU_ATTR_REMCSUM_NOPARTIAL` set. iproute2 has no CLI
// option for the flag, the listener was created with a raw generic netlink
// message carrying the `FOU_ATTR_REMCSUM_NOPARTIAL` flag attribute.
// Generic netlink `FOU_CMD_GET` reply with AF, PORT, PEER_PORT, IPPROTO,
// TYPE, IFINDEX, REMCSUM_NOPARTIAL, LOCAL_V4 and PEER_V4.
#[test]
fn test_parse_kernel_reply_remcsum_nopartial() {
    let raw: Vec<u8> = vec![
        0x03, 0x01, 0x00, 0x00, // genlmsghdr: FOU_CMD_GET, version 1
        0x05, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, // af inet
        0x06, 0x00, 0x01, 0x00, 0x03, 0xea, 0x00, 0x00, // port 1002
        0x06, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, // peer port 0
        0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // ipproto 0
        0x05, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, // gue
        0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, // ifindex 0
        0x04, 0x00, 0x05, 0x00, // remcsum nopartial
        0x08, 0x00, 0x06, 0x00, 0x0a, 0x09, 0x09, 0x01, // local 10.9.9.1
        0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // peer 0.0.0.0
    ];

    assert_parse_and_emit(
        &raw,
        &FouMessage {
            cmd: FouCmd::Get,
            attributes: vec![
                FouAttribute::Family(FouAddressFamily::Ipv4),
                FouAttribute::Port(1002),
                FouAttribute::PeerPort(0),
                FouAttribute::Ipproto(0),
                FouAttribute::Encap(FouEncap::Gue),
                FouAttribute::IfIndex(0),
                FouAttribute::RemcsumNopartial,
                FouAttribute::LocalV4(Ipv4Addr::new(10, 9, 9, 1)),
                FouAttribute::PeerV4(Ipv4Addr::UNSPECIFIED),
            ],
        },
    );
}

// nlmon capture of the request sent by `sudo ip fou show`: a generic
// netlink `FOU_CMD_GET` request with the `NLM_F_DUMP` flag and no
// attributes.
#[test]
fn test_parse_kernel_dump_request() {
    let raw: Vec<u8> = vec![
        0x03, 0x01, 0x00, 0x00, // genlmsghdr: FOU_CMD_GET, version 1
    ];

    assert_parse_and_emit(
        &raw,
        &FouMessage {
            cmd: FouCmd::Get,
            attributes: vec![],
        },
    );
}

#[test]
fn test_family_name() {
    assert_eq!(FouMessage::family_name(), "fou");
}
