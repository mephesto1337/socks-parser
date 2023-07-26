use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use nom::{
    combinator::{map, map_opt},
    error::context,
    multi::length_data,
    number::complete::be_u8,
};

use crate::Wire;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AddressType {
    IPv4(Ipv4Addr),
    DomainName(String),
    IPv6(Ipv6Addr),
}

impl Wire for AddressType {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::IPv4(ref ip4) => {
                buffer.push(1);
                ip4.encode_into(buffer);
            }
            Self::IPv6(ref ip6) => {
                buffer.push(4);
                ip6.encode_into(buffer);
            }
            Self::DomainName(ref name) => {
                buffer.push(3);
                let size: u8 = name.len().try_into().expect("Domain name too long");
                buffer.push(size);
                buffer.extend_from_slice(name.as_bytes());
            }
        }
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        let (rest, address_type) = context("address type", be_u8)(buffer)?;

        match address_type {
            1 => map(Ipv4Addr::decode, Self::IPv4)(rest),
            3 => context(
                "domain name",
                map_opt(length_data(be_u8), |b| {
                    std::str::from_utf8(b)
                        .ok()
                        .map(|s| Self::DomainName(s.to_owned()))
                }),
            )(rest),
            4 => map(Ipv6Addr::decode, Self::IPv6)(rest),
            _ => Err(nom::Err::Failure(E::add_context(
                buffer,
                "Invalid address type",
                nom::error::make_error(buffer, nom::error::ErrorKind::NoneOf),
            ))),
        }
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IPv4(ref ip4) => fmt::Display::fmt(ip4, f),
            Self::IPv6(ref ip6) => write!(f, "[{}]", ip6),
            Self::DomainName(ref name) => f.write_str(name),
        }
    }
}

impl From<IpAddr> for AddressType {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip4) => Self::IPv4(ip4),
            IpAddr::V6(ip6) => Self::IPv6(ip6),
        }
    }
}
