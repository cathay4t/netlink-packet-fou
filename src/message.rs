// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, NlasIterator, Parseable,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::FouAttribute;

/// Add a FOU listener.
const FOU_CMD_ADD: u8 = 1;
/// Delete a FOU listener.
const FOU_CMD_DEL: u8 = 2;
/// Get or dump FOU listeners.
const FOU_CMD_GET: u8 = 3;

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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attributes.as_slice().emit(out)
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
    for nla in NlasIterator::new(buf)? {
        attributes.push(FouAttribute::parse(&nla).context(error_msg)?);
    }
    Ok(attributes)
}
