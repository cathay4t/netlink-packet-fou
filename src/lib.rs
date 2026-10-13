// SPDX-License-Identifier: MIT

//! The `netlink-packet-fou` crate is designed to parse and emit generic
//! netlink packets of the FOU (foo over UDP) family. The goal of this crate
//! is saving crate users from reading the kernel netlink code.
//!
//! The FOU generic netlink family is defined in
//! `Documentation/netlink/specs/fou.yaml` of the Linux kernel and
//! `include/uapi/linux/fou.h`.
//!
//! ```no_run
//! use netlink_packet_fou::{FouAttribute, FouCmd, FouMessage};
//!
//! let message = FouMessage {
//!     cmd: FouCmd::Add,
//!     attributes: vec![
//!         FouAttribute::Port(5555),
//!         FouAttribute::Ipproto(17),
//!     ],
//! };
//! ```

mod attribute;
mod message;
#[cfg(test)]
mod test;

pub use attribute::{
    FOU_ENCAP_DIRECT, FOU_ENCAP_GUE, FOU_ENCAP_UNSPEC, FouAddressFamily,
    FouAttribute, FouEncap,
};
pub use message::{FOU_CMD_ADD, FOU_CMD_DEL, FOU_CMD_GET, FouCmd, FouMessage};
