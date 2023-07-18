use nom::{
    combinator::{map, map_opt, verify},
    error::context,
    number::streaming::be_u8,
};

use super::Wire;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Version {
    Socks5 = 5,
}

impl Wire for Version {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self as u8);
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        context(
            "SocksVersion",
            map(verify(be_u8, |b| *b == Self::Socks5 as u8), |_| {
                Self::Socks5
            }),
        )(buffer)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthenticationMethod {
    None,
    Gssapi,
    UsernamePassword,
    IanaAssigned(u8),
    PrivateMethod(u8),
    NotAcceptable,
}

impl From<u8> for AuthenticationMethod {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Gssapi,
            2 => Self::UsernamePassword,
            3..=0x7f => Self::IanaAssigned(value),
            0x80..=0xfe => Self::PrivateMethod(value),
            0xff => Self::NotAcceptable,
        }
    }
}

impl AuthenticationMethod {
    fn as_u8(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Gssapi => 1,
            Self::UsernamePassword => 2,
            Self::IanaAssigned(v) => *v,
            Self::PrivateMethod(v) => *v,
            Self::NotAcceptable => 0xff,
        }
    }
}

impl Wire for AuthenticationMethod {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(self.as_u8());
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        context("SocksVersion", map(be_u8, Self::from))(buffer)
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Command {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

impl Command {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Connect),
            2 => Some(Self::Bind),
            3 => Some(Self::UdpAssociate),
            _ => None,
        }
    }
}

impl Wire for Command {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self as u8);
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        context("Socks command", map_opt(be_u8, Self::from_u8))(buffer)
    }
}

mod address_type;
pub use address_type::AddressType;
