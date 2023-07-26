use std::{io, net::Ipv4Addr};

use nom::{error::context, number::complete::be_u8};

use crate::Wire;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Command {
    Connect = 1,
    Bind = 2,
}

impl Wire for Command {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self as u8);
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        let (rest, command) = context("Socks V5 command", be_u8)(buffer)?;
        match command {
            1 => Ok((rest, Self::Connect)),
            2 => Ok((rest, Self::Bind)),
            _ => Err(nom::Err::Failure(nom::error::make_error(
                buffer,
                nom::error::ErrorKind::NoneOf,
            ))),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AddressType {
    IPv4(Ipv4Addr),
    DomainName(String),
}

impl TryFrom<super::v5::AddressType> for AddressType {
    type Error = io::Error;

    fn try_from(value: super::v5::AddressType) -> Result<Self, Self::Error> {
        match value {
            super::v5::AddressType::IPv4(ip4) => Ok(Self::IPv4(ip4)),
            super::v5::AddressType::DomainName(n) => Ok(Self::DomainName(n)),
            super::v5::AddressType::IPv6(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Socks v4 does not support IPv6",
            )),
        }
    }
}
