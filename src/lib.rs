use std::net::SocketAddr;

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

    impl From<Request> for super::ConnectionRequest {
        fn from(value: Request) -> Self {
            let addr = match value.addr {
                AddressType::IPv4(ip4) => crate::v5::AddressType::IPv4(ip4),
                AddressType::DomainName(n) => crate::v5::AddressType::DomainName(n),
            };
            super::ConnectionRequest {
                destination: super::Destination {
                    addr,
                    port: value.port,
                },
            }
        }
    }

    impl From<super::ConnectionResponse> for Response {
        fn from(value: super::ConnectionResponse) -> Self {
            let addr = match value.connected_to.addr {
                crate::common::v5::AddressType::IPv4(ip4) => ip4,
                _ => 0u32.into(),
            };
            Self {
                status: match value.status {
                    crate::v5::Status::Success => Status::Success,
                    _ => Status::Rejected,
                },
                addr,
                port: value.connected_to.port,
            }
        }
    }
}

pub mod v5 {
    pub use crate::common::{
        v5::{AddressType, AuthenticationMethod, Command},
        Version,
    };
    pub use crate::request::v5::{Hello, Request};
    pub use crate::response::v5::{Hello as HelloResponse, Response, Status};

    impl From<Request> for super::ConnectionRequest {
        fn from(value: Request) -> Self {
            super::ConnectionRequest {
                destination: super::Destination {
                    addr: value.addr,
                    port: value.port,
                },
            }
        }
    }

    impl From<super::ConnectionResponse> for Response {
        fn from(value: super::ConnectionResponse) -> Self {
            Self {
                status: value.status,
                addr: value.connected_to.addr,
                port: value.connected_to.port,
            }
        }
    }

    impl From<crate::v4::AddressType> for AddressType {
        fn from(value: crate::v4::AddressType) -> Self {
            match value {
                crate::common::v4::AddressType::IPv4(ip4) => Self::IPv4(ip4),
                crate::common::v4::AddressType::DomainName(n) => Self::DomainName(n),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub addr: v5::AddressType,
    pub port: u16,
}

impl From<(v5::AddressType, u16)> for Destination {
    fn from(value: (v5::AddressType, u16)) -> Self {
        Self {
            addr: value.0,
            port: value.1,
        }
    }
}

impl From<(v4::AddressType, u16)> for Destination {
    fn from(value: (v4::AddressType, u16)) -> Self {
        Self {
            addr: value.0.into(),
            port: value.1,
        }
    }
}

impl From<SocketAddr> for Destination {
    fn from(value: SocketAddr) -> Self {
        let addr = value.ip().into();
        Self {
            addr,
            port: value.port(),
        }
    }
}

impl<T: Into<Destination>> From<T> for ConnectionRequest {
    fn from(value: T) -> Self {
        Self {
            destination: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub destination: Destination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionResponse {
    pub connected_to: Destination,
    pub status: v5::Status,
}

trait Wire: Sized {
    fn encode_into(&self, buffer: &mut Vec<u8>);
    fn decode<'i, E>(input: &'i [u8]) -> nom::IResult<&'i [u8], Self, E>
    where
        E: nom::error::ParseError<&'i [u8]> + nom::error::ContextError<&'i [u8]>;
}
