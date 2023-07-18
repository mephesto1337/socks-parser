use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt},
    error::context,
    number::streaming::be_u8,
};

use crate::Wire;

#[derive(Debug, PartialEq, Eq)]
pub enum AddressType {
    IPv4(Ipv4Addr),
    DomainName(String),
    IPv6(Ipv6Addr),
}

fn encode_hostname(buffer: &mut Vec<u8>, name: &str) {
    let name_sz: u8 = name.len().try_into().expect("Name too long");
    buffer.push(name_sz);
    buffer.extend_from_slice(name.as_bytes());
}

fn decode_hostname<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], String, E>
where
    E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
{
    let (rest, name_len) = be_u8(buffer)?;
    let (rest, name) = map_opt(take(name_len as usize), |b| {
        std::str::from_utf8(b).map(|s| s.to_owned()).ok()
    })(rest)?;
    Ok((rest, name))
}

fn encode_ipv4(ip4: &Ipv4Addr, buffer: &mut Vec<u8>) {
    for b in ip4.octets() {
        buffer.push(b);
    }
}

fn decode_ipv4<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Ipv4Addr, E>
where
    E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
{
    let mut octets = [0u8; 4];
    let (rest, bytes) = take(4usize)(buffer)?;
    octets.copy_from_slice(bytes);
    Ok((rest, Ipv4Addr::from(octets)))
}

fn encode_ipv6(ip6: &Ipv6Addr, buffer: &mut Vec<u8>) {
    for b in ip6.octets() {
        buffer.push(b);
    }
}

fn decode_ipv6<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Ipv6Addr, E>
where
    E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
{
    let mut octets = [0u8; 16];
    let (rest, bytes) = take(16usize)(buffer)?;
    octets.copy_from_slice(bytes);
    Ok((rest, Ipv6Addr::from(octets)))
}

impl Wire for AddressType {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::IPv4(ref ip4) => {
                buffer.push(1);
                encode_ipv4(ip4, buffer);
            }
            Self::IPv6(ref ip6) => {
                buffer.push(4);
                encode_ipv6(ip6, buffer);
            }
            Self::DomainName(ref name) => {
                buffer.push(3);
                encode_hostname(buffer, name);
            }
        }
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        let (rest, address_type) = context("Socks address type", be_u8)(buffer)?;

        match address_type {
            1 => context("Socks address IPv4", map(decode_ipv4, Self::IPv4))(rest),
            3 => context(
                "Socks address domain name",
                map(decode_hostname, Self::DomainName),
            )(rest),
            4 => context("Socks address IPv6", map(decode_ipv6, Self::IPv6))(rest),
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
