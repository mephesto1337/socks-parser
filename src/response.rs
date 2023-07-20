pub mod v4 {
    use std::net::Ipv4Addr;

    use nom::{
        combinator::verify,
        error::context,
        number::streaming::{be_u16, be_u8},
        sequence::{preceded, tuple},
    };

    use crate::Wire;

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[repr(u8)]
    pub enum Status {
        Success = 0x5a,
        Rejected = 0x5b,
        InetdNotAccessible = 0x5c,
        InetdNotIdentified = 0x5d,
    }

    impl Wire for Status {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            buffer.push(*self as u8);
        }

        fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            let (rest, s) = context("status", be_u8)(buffer)?;
            match s {
                0x5a => Ok((rest, Self::Success)),
                0x5b => Ok((rest, Self::Rejected)),
                0x5c => Ok((rest, Self::InetdNotAccessible)),
                0x5d => Ok((rest, Self::InetdNotIdentified)),
                _ => Err(nom::Err::Failure(nom::error::make_error(
                    buffer,
                    nom::error::ErrorKind::NoneOf,
                ))),
            }
        }
    }

    #[derive(Debug)]
    pub struct Response {
        pub status: Status,
        pub addr: Ipv4Addr,
        pub port: u16,
    }

    impl Wire for Response {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            buffer.push(0);
            self.status.encode_into(buffer);
            buffer.extend_from_slice(&self.port.to_be_bytes()[..]);
            self.addr.encode_into(buffer);
        }

        fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            let (rest, (status, port, addr)) = context(
                "response",
                preceded(
                    verify(be_u8, |&b| b == 0),
                    tuple((Status::decode, be_u16, Ipv4Addr::decode)),
                ),
            )(buffer)?;
            Ok((rest, Self { status, addr, port }))
        }
    }
}

pub mod v5 {
    use nom::{
        combinator::{map, verify},
        error::context,
        number::streaming::{be_u16, be_u8},
        sequence::{preceded, tuple},
    };

    use crate::{
        common::{
            v5::{AddressType, AuthenticationMethod},
            Version,
        },
        Wire,
    };

    #[derive(Debug)]
    pub struct Hello {
        pub method: AuthenticationMethod,
    }

    impl Wire for Hello {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            Version::Socks5.encode_into(buffer);
            self.method.encode_into(buffer);
        }

        fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            context(
                "Hello response",
                map(
                    preceded(
                        verify(Version::decode, |&v| v == Version::Socks5),
                        AuthenticationMethod::decode,
                    ),
                    |method| Self { method },
                ),
            )(buffer)
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

    impl Wire for Status {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            let b = match self {
                Self::Success => 0,
                Self::GeneralFailure => 1,
                Self::ConnectionNotAllowed => 2,
                Self::NetworkUnreachable => 3,
                Self::HostUnreachalble => 4,
                Self::ConnectionRefused => 5,
                Self::TTLExpired => 6,
                Self::CommandNotSupported => 7,
                Self::Unassigned(v) => *v,
            };
            buffer.push(b);
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
        pub status: Status,
        pub addr: AddressType,
        pub port: u16,
    }

    impl Wire for Response {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            Version::Socks5.encode_into(buffer);
            self.status.encode_into(buffer);
            buffer.push(0);
            self.addr.encode_into(buffer);
            buffer.extend_from_slice(&self.port.to_be_bytes()[..]);
        }

        fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            let (rest, (status, _zero, addr, port)) = context(
                "Socks response",
                preceded(
                    verify(Version::decode, |&v| v == Version::Socks5),
                    tuple((Status::decode, be_u8, AddressType::decode, be_u16)),
                ),
            )(buffer)?;
            Ok((rest, Self { status, addr, port }))
        }
    }
}
