// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, Parseable,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::FouAttribute;

/// Add a FOU listener.
pub const FOU_CMD_ADD: u8 = 1;
/// Delete a FOU listener.
pub const FOU_CMD_DEL: u8 = 2;
/// Get or dump FOU listeners.
pub const FOU_CMD_GET: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FouCmd {
    Add,
    Del,
    Get,
    Other(u8),
}

impl From<FouCmd> for u8 {
    fn from(cmd: FouCmd) -> Self {
        match cmd {
            FouCmd::Add => FOU_CMD_ADD,
            FouCmd::Del => FOU_CMD_DEL,
            FouCmd::Get => FOU_CMD_GET,
            FouCmd::Other(cmd) => cmd,
        }
    }
}

impl From<u8> for FouCmd {
    fn from(value: u8) -> Self {
        match value {
            FOU_CMD_ADD => Self::Add,
            FOU_CMD_DEL => Self::Del,
            FOU_CMD_GET => Self::Get,
            cmd => Self::Other(cmd),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FouMessage {
    pub cmd: FouCmd,
    pub attributes: Vec<FouAttribute>,
}

impl FouMessage {
    pub fn new(cmd: FouCmd) -> Self {
        Self {
            cmd,
            attributes: Vec::new(),
        }
    }
}

impl GenlFamily for FouMessage {
    fn family_name() -> &'static str {
        "fou"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Emitable for FouMessage {
    fn emit(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for FouMessage {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes(buf)?,
        })
    }
}

fn parse_attributes(buf: &[u8]) -> Result<Vec<FouAttribute>, DecodeError> {
    let mut attributes = Vec::new();
    let error_msg = "failed to parse fou netlink attributes";
    for nla in NlasIterator::new(buf) {
        let nla = &nla.context(error_msg)?;
        attributes.push(FouAttribute::parse(nla)?);
    }
    Ok(attributes)
}
