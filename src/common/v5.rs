use nom::{combinator::map, error::context, number::complete::be_u8};

use crate::Wire;

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
            3 => Ok((rest, Self::UdpAssociate)),
            _ => Err(nom::Err::Failure(nom::error::make_error(
                buffer,
                nom::error::ErrorKind::NoneOf,
            ))),
        }
    }
}

mod address_type;
pub use address_type::AddressType;
