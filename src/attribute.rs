// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{
    DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer, Parseable, emit_i32,
    emit_u16_be, parse_i32, parse_u8, parse_u16_be,
};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const FOU_ATTR_PORT: u16 = 1;
const FOU_ATTR_AF: u16 = 2;
const FOU_ATTR_IPPROTO: u16 = 3;
const FOU_ATTR_TYPE: u16 = 4;
const FOU_ATTR_REMCSUM_NOPARTIAL: u16 = 5;
const FOU_ATTR_LOCAL_V4: u16 = 6;
const FOU_ATTR_LOCAL_V6: u16 = 7;
const FOU_ATTR_PEER_V4: u16 = 8;
const FOU_ATTR_PEER_V6: u16 = 9;
const FOU_ATTR_PEER_PORT: u16 = 10;
const FOU_ATTR_IFINDEX: u16 = 11;

/// Foo over UDP.
const FOU_ENCAP_DIRECT: u8 = 1;
/// Generic UDP encapsulation.
const FOU_ENCAP_GUE: u8 = 2;

/// Encapsulation type of a FOU listener, see `FOU_ENCAP_*` of the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FouEncap {
    /// Foo over UDP.
    Direct,
    /// Generic UDP encapsulation.
    Gue,
    Other(u8),
}

impl From<u8> for FouEncap {
    fn from(value: u8) -> Self {
        match value {
            FOU_ENCAP_DIRECT => Self::Direct,
            FOU_ENCAP_GUE => Self::Gue,
            value => Self::Other(value),
        }
    }
}

impl From<FouEncap> for u8 {
    fn from(value: FouEncap) -> Self {
        match value {
            FouEncap::Direct => FOU_ENCAP_DIRECT,
            FouEncap::Gue => FOU_ENCAP_GUE,
            FouEncap::Other(value) => value,
        }
    }
}

/// Address family of a FOU listener, see `FOU_ATTR_AF` of the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FouAddressFamily {
    Ipv4,
    Ipv6,
    Other(u8),
}

impl From<u8> for FouAddressFamily {
    fn from(value: u8) -> Self {
        match value {
            AF_INET => Self::Ipv4,
            AF_INET6 => Self::Ipv6,
            value => Self::Other(value),
        }
    }
}

impl From<FouAddressFamily> for u8 {
    fn from(value: FouAddressFamily) -> Self {
        match value {
            FouAddressFamily::Ipv4 => AF_INET,
            FouAddressFamily::Ipv6 => AF_INET6,
            FouAddressFamily::Other(value) => value,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FouAttribute {
    /// The local UDP port, a network byte order `u16`.
    Port(u16),
    Family(FouAddressFamily),
    /// The L4 protocol to receive, `FOU_ATTR_IPPROTO`.
    Ipproto(u8),
    Encap(FouEncap),
    /// Receive checksum not partial, a flag attribute.
    RemcsumNopartial,
    LocalV4(Ipv4Addr),
    LocalV6(Ipv6Addr),
    PeerV4(Ipv4Addr),
    PeerV6(Ipv6Addr),
    /// The peer UDP port, a network byte order `u16`.
    PeerPort(u16),
    IfIndex(i32),
    Other(DefaultNla),
}

impl Nla for FouAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Port(_) | Self::PeerPort(_) => 2,
            Self::Family(_) | Self::Ipproto(_) | Self::Encap(_) => 1,
            Self::RemcsumNopartial => 0,
            Self::LocalV4(_) | Self::PeerV4(_) => 4,
            Self::LocalV6(_) | Self::PeerV6(_) => 16,
            Self::IfIndex(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Port(_) => FOU_ATTR_PORT,
            Self::Family(_) => FOU_ATTR_AF,
            Self::Ipproto(_) => FOU_ATTR_IPPROTO,
            Self::Encap(_) => FOU_ATTR_TYPE,
            Self::RemcsumNopartial => FOU_ATTR_REMCSUM_NOPARTIAL,
            Self::LocalV4(_) => FOU_ATTR_LOCAL_V4,
            Self::LocalV6(_) => FOU_ATTR_LOCAL_V6,
            Self::PeerV4(_) => FOU_ATTR_PEER_V4,
            Self::PeerV6(_) => FOU_ATTR_PEER_V6,
            Self::PeerPort(_) => FOU_ATTR_PEER_PORT,
            Self::IfIndex(_) => FOU_ATTR_IFINDEX,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Port(port) | Self::PeerPort(port) => {
                emit_u16_be(buffer, *port).unwrap()
            }
            Self::Family(family) => buffer[0] = (*family).into(),
            Self::Ipproto(ipproto) => buffer[0] = *ipproto,
            Self::Encap(encap) => buffer[0] = (*encap).into(),
            Self::RemcsumNopartial => (),
            Self::LocalV4(addr) | Self::PeerV4(addr) => {
                buffer.copy_from_slice(&addr.octets())
            }
            Self::LocalV6(addr) | Self::PeerV6(addr) => {
                buffer.copy_from_slice(&addr.octets())
            }
            Self::IfIndex(index) => emit_i32(buffer, *index).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for FouAttribute {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            FOU_ATTR_PORT => Self::Port(
                parse_u16_be(payload).context("invalid FOU_ATTR_PORT value")?,
            ),
            FOU_ATTR_AF => Self::Family(
                parse_u8(payload)
                    .context("invalid FOU_ATTR_AF value")?
                    .into(),
            ),
            FOU_ATTR_IPPROTO => Self::Ipproto(
                parse_u8(payload).context("invalid FOU_ATTR_IPPROTO value")?,
            ),
            FOU_ATTR_TYPE => Self::Encap(
                parse_u8(payload)
                    .context("invalid FOU_ATTR_TYPE value")?
                    .into(),
            ),
            FOU_ATTR_REMCSUM_NOPARTIAL => Self::RemcsumNopartial,
            FOU_ATTR_LOCAL_V4 => Self::LocalV4(
                parse_ipv4(payload)
                    .context("invalid FOU_ATTR_LOCAL_V4 value")?,
            ),
            FOU_ATTR_LOCAL_V6 => Self::LocalV6(
                parse_ipv6(payload)
                    .context("invalid FOU_ATTR_LOCAL_V6 value")?,
            ),
            FOU_ATTR_PEER_V4 => Self::PeerV4(
                parse_ipv4(payload)
                    .context("invalid FOU_ATTR_PEER_V4 value")?,
            ),
            FOU_ATTR_PEER_V6 => Self::PeerV6(
                parse_ipv6(payload)
                    .context("invalid FOU_ATTR_PEER_V6 value")?,
            ),
            FOU_ATTR_PEER_PORT => Self::PeerPort(
                parse_u16_be(payload)
                    .context("invalid FOU_ATTR_PEER_PORT value")?,
            ),
            FOU_ATTR_IFINDEX => Self::IfIndex(
                parse_i32(payload).context("invalid FOU_ATTR_IFINDEX value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}

fn parse_ipv4(payload: &[u8]) -> Result<Ipv4Addr, DecodeError> {
    let octets: [u8; 4] =
        payload
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| {
                DecodeError::from(e.to_string())
            })?;
    Ok(Ipv4Addr::from(octets))
}

fn parse_ipv6(payload: &[u8]) -> Result<Ipv6Addr, DecodeError> {
    let octets: [u8; 16] =
        payload
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| {
                DecodeError::from(e.to_string())
            })?;
    Ok(Ipv6Addr::from(octets))
}
