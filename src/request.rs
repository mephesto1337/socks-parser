pub mod v4 {
    use std::net::Ipv4Addr;

    use nom::{
        bytes::complete::{tag, take_while1},
        combinator::{map, opt, verify},
        error::{context, ContextError},
        number::complete::{be_u16, be_u8},
        sequence::{preceded, terminated, tuple},
    };

    use crate::{
        common::{
            v4::{AddressType, Command},
            Version,
        },
        Wire,
    };

    #[derive(Debug)]
    pub struct Request {
        pub command: Command,
        pub addr: AddressType,
        pub port: u16,
        pub secret: Option<String>,
    }

    fn encode_string(s: Option<&str>, buffer: &mut Vec<u8>) {
        if let Some(s) = s {
            buffer.extend_from_slice(s.as_bytes());
        }
        buffer.push(0);
    }

    fn decode_string<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Option<String>, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        context(
            "string",
            map(
                terminated(opt(take_while1(|b: u8| b.is_ascii() && b != 0)), tag(b"\0")),
                |b: Option<&[u8]>| {
                    b.and_then(|x| std::str::from_utf8(x).ok())
                        .map(String::from)
                },
            ),
        )(buffer)
    }

    impl Wire for Request {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            Version::Socks4.encode_into(buffer);
            self.command.encode_into(buffer);
            buffer.extend_from_slice(&self.port.to_be_bytes()[..]);
            match self.addr {
                AddressType::IPv4(ip4) => {
                    buffer.extend_from_slice(&ip4.octets()[..]);
                    encode_string(self.secret.as_deref(), buffer);
                }
                AddressType::DomainName(ref n) => {
                    buffer.extend_from_slice(&[0, 0, 0, 1][..]);
                    encode_string(self.secret.as_deref(), buffer);
                    encode_string(Some(n.as_str()), buffer);
                }
            }
        }

        fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            log::trace!("v4::Request::decode({buffer:?})");
            let (rest, (command, port, (a, b, c, d), secret, name)) = context(
                "Socks request",
                preceded(
                    verify(Version::decode, |&v| v == Version::Socks4),
                    tuple((
                        Command::decode,
                        be_u16,
                        tuple((be_u8, be_u8, be_u8, be_u8)),
                        decode_string,
                        opt(decode_string),
                    )),
                ),
            )(buffer)?;
            let addr = match name {
                Some(Some(n)) => AddressType::DomainName(n),
                Some(None) => {
                    return Err(nom::Err::Failure(ContextError::add_context(
                        buffer,
                        "Got empty domain name",
                        nom::error::make_error(buffer, nom::error::ErrorKind::Verify),
                    )));
                }
                None => AddressType::IPv4(Ipv4Addr::new(a, b, c, d)),
            };

            Ok((
                rest,
                Self {
                    command,
                    addr,
                    port,
                    secret,
                },
            ))
        }
    }
}

pub mod v5 {
    use nom::{
        combinator::{map, verify},
        error::context,
        multi::length_count,
        number::complete::{be_u16, be_u8},
        sequence::{preceded, tuple},
    };

    use crate::{
        common::{
            v5::{AddressType, AuthenticationMethod, Command},
            Version,
        },
        Wire,
    };

    #[derive(Debug)]
    pub struct Hello {
        pub methods: Vec<AuthenticationMethod>,
    }

    impl Wire for Hello {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            Version::Socks5.encode_into(buffer);
            buffer.push(
                self.methods
                    .len()
                    .try_into()
                    .expect("Too many available methods"),
            );
            for m in &self.methods {
                m.encode_into(buffer);
            }
        }

        fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            context(
                "Hello",
                map(
                    preceded(
                        verify(Version::decode, |&v| v == Version::Socks5),
                        length_count(be_u8, AuthenticationMethod::decode),
                    ),
                    |methods| Self { methods },
                ),
            )(buffer)
        }
    }

    #[derive(Debug)]
    pub struct Request {
        pub command: Command,
        pub addr: AddressType,
        pub port: u16,
    }

    impl Wire for Request {
        fn encode_into(&self, buffer: &mut Vec<u8>) {
            Version::Socks5.encode_into(buffer);
            self.command.encode_into(buffer);
            buffer.push(0);
            self.addr.encode_into(buffer);
            buffer.extend_from_slice(&self.port.to_be_bytes()[..]);
        }

        fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            log::trace!("v5::Request::decode({buffer:?})");
            let (rest, (command, _zero, addr, port)) = context(
                "Request",
                preceded(
                    verify(Version::decode, |&v| v == Version::Socks5),
                    tuple((Command::decode, be_u8, AddressType::decode, be_u16)),
                ),
            )(buffer)?;
            Ok((
                rest,
                Self {
                    command,
                    addr,
                    port,
                },
            ))
        }
    }
}
