use nom::{
    combinator::map,
    error::context,
    multi::length_count,
    number::streaming::{be_u16, be_u8},
    sequence::tuple,
};

use crate::{
    common::{AddressType, AuthenticationMethod, Command, Version},
    Wire,
};

#[derive(Debug)]
pub struct Hello {
    pub version: Version,
    pub methods: Vec<AuthenticationMethod>,
}

impl Wire for Hello {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        self.version.encode_into(buffer);
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
            "Hello request",
            map(
                tuple((
                    Version::decode,
                    length_count(be_u8, AuthenticationMethod::decode),
                )),
                |(version, methods)| Self { version, methods },
            ),
        )(buffer)
    }
}

#[derive(Debug)]
pub struct Request {
    pub version: Version,
    pub command: Command,
    pub addr: AddressType,
    pub port: u16,
}

impl Wire for Request {
    fn encode_into(&self, buffer: &mut Vec<u8>) {
        self.version.encode_into(buffer);
        self.command.encode_into(buffer);
        buffer.push(0);
        self.addr.encode_into(buffer);
        buffer.extend_from_slice(&self.port.to_be_bytes()[..]);
    }

    fn decode<'i, E>(buffer: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
    {
        let (rest, (version, command, _zero, addr, port)) = context(
            "Socks request",
            tuple((
                Version::decode,
                Command::decode,
                be_u8,
                AddressType::decode,
                be_u16,
            )),
        )(buffer)?;
        Ok((
            rest,
            Self {
                version,
                command,
                addr,
                port,
            },
        ))
    }
}
