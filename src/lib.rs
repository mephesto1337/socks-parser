mod common;
pub mod request;
pub mod response;

pub use common::*;

pub use nom;

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
    request::Hello,
    encode_socks_request_hello,
    decode_socks_request_hello
);
impl_encoder_decoder!(
    response::Hello,
    encode_socks_response_hello,
    decode_socks_response_hello
);
impl_encoder_decoder!(request::Request, encode_socks_request, decode_socks_request);
impl_encoder_decoder!(
    response::Response,
    encode_socks_response,
    decode_socks_response
);
