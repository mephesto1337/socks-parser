use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    combinator::map,
    error::context,
    number::complete::{be_u16, be_u8},
    sequence::tuple,
};

use super::Wire;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Version {
    Socks4 = 4,
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
        let (rest, version) = context("Socks version", be_u8)(buffer)?;
        match version {
            4 => Ok((rest, Self::Socks4)),
            5 => Ok((rest, Self::Socks5)),
            _ => Err(nom::Err::Failure(nom::error::make_error(
                buffer,
                nom::error::ErrorKind::NoneOf,
            ))),
        }
    }
}

impl Wire for Ipv4Addr {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.octets()[..]);
    }

    fn decode<'i, E>(input: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        context(
            "IPv4",
            map(tuple((be_u8, be_u8, be_u8, be_u8)), |(a, b, c, d)| {
                Self::new(a, b, c, d)
            }),
        )(input)
    }
}

impl Wire for Ipv6Addr {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.octets()[..]);
    }

    fn decode<'i, E>(input: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        context(
            "IPv6",
            map(
                tuple((
                    be_u16, be_u16, be_u16, be_u16, be_u16, be_u16, be_u16, be_u16,
                )),
                |(a, b, c, d, e, f, g, h)| Self::new(a, b, c, d, e, f, g, h),
            ),
        )(input)
    }
}

pub mod v4;
pub mod v5;
