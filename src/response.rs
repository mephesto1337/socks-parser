use nom::{
    combinator::map,
    error::context,
    number::streaming::{be_u16, be_u8},
    sequence::tuple,
};

use crate::{
    common::{AddressType, AuthenticationMethod, Version},
    Wire,
};

#[derive(Debug)]
pub struct Hello {
    pub version: Version,
    pub method: AuthenticationMethod,
}

impl Wire for Hello {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        self.version.encode_into(buffer);
        self.method.encode_into(buffer);
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        let (rest, (version, method)) =
            tuple((Version::decode, AuthenticationMethod::decode))(buffer)?;
        Ok((rest, Self { version, method }))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    Success,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachalble,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupported,
    Unassigned(u8),
}

impl From<u8> for Status {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Success,
            1 => Self::GeneralFailure,
            2 => Self::ConnectionNotAllowed,
            3 => Self::NetworkUnreachable,
            4 => Self::HostUnreachalble,
            5 => Self::ConnectionRefused,
            6 => Self::TTLExpired,
            7 => Self::CommandNotSupported,
            v => Self::Unassigned(v),
        }
    }
}

impl Status {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Success => 0,
            Self::GeneralFailure => 1,
            Self::ConnectionNotAllowed => 2,
            Self::NetworkUnreachable => 3,
            Self::HostUnreachalble => 4,
            Self::ConnectionRefused => 5,
            Self::TTLExpired => 6,
            Self::CommandNotSupported => 7,
            Self::Unassigned(v) => *v,
        }
    }
}

impl Wire for Status {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(self.as_u8());
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        context("Socks status", map(be_u8, Self::from))(buffer)
    }
}

#[derive(Debug)]
pub struct Response {
    pub version: Version,
    pub status: Status,
    pub addr: AddressType,
    pub port: u16,
}

impl Wire for Response {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        self.version.encode_into(buffer);
        self.status.encode_into(buffer);
        buffer.push(0);
        self.addr.encode_into(buffer);
        buffer.extend_from_slice(&self.port.to_be_bytes()[..]);
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        let (rest, (version, status, _zero, addr, port)) = context(
            "Socks response",
            tuple((
                Version::decode,
                Status::decode,
                be_u8,
                AddressType::decode,
                be_u16,
            )),
        )(buffer)?;
        Ok((
            rest,
            Self {
                version,
                status,
                addr,
                port,
            },
        ))
    }
}
