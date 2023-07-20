pub mod common;
mod request;
mod response;

#[cfg(feature = "async")]
mod client;
#[cfg(feature = "async")]
pub use client::Client;
#[cfg(feature = "async")]
mod server;
pub use server::Server;

pub use common::Version;

pub use nom;

pub mod v4 {
    pub use crate::common::{
        v4::{AddressType, Command},
        Version,
    };
    pub use crate::request::v4::Request;
    pub use crate::response::v4::{Response, Status};
}

pub mod v5 {
    pub use crate::common::{
        v5::{AddressType, AuthenticationMethod, Command},
        Version,
    };
    pub use crate::request::v5::{Hello, Request};
    pub use crate::response::v5::{Hello as HelloResponse, Response, Status};
}

trait Wire: Sized {
    fn encode_into(&self, buffer: &mut Vec<u8>);
    fn decode<'i, E>(input: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>;
}

macro_rules! impl_encoder_decoder {
    ($type:path, $encoder:ident, $decoder:ident) => {
        pub fn $decoder<'i, E>(input: &'i [u8]) -> nom::IResult<&'i [u8], $type, E>
        where
            E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>,
        {
            <$type>::decode(input)
        }

        pub fn $encoder(this: &$type, buffer: &mut Vec<u8>) {
            this.encode_into(buffer);
        }
    };
}

impl_encoder_decoder!(
    request::v5::Hello,
    encode_socks5_request_hello,
    decode_socks5_request_hello
);
impl_encoder_decoder!(
    response::v5::Hello,
    encode_socks5_response_hello,
    decode_socks5_response_hello
);
impl_encoder_decoder!(
    request::v5::Request,
    encode_socks5_request,
    decode_socks5_request
);
impl_encoder_decoder!(
    response::v5::Response,
    encode_socks5_response,
    decode_socks5_response
);
