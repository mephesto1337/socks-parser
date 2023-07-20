use std::{io, net::SocketAddr};

use crate::{Version, Wire};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn map_nom_error(e: nom::Err<nom::error::VerboseError<&[u8]>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e:x?}"))
}

pub struct Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream: S,
    version: Version,
}

pub trait IntoSocksAddr {
    fn into_socks_addr(self) -> (crate::common::v5::AddressType, u16);
}

impl IntoSocksAddr for SocketAddr {
    fn into_socks_addr(self) -> (crate::common::v5::AddressType, u16) {
        (self.ip().into(), self.port())
    }
}

impl IntoSocksAddr for (String, u16) {
    fn into_socks_addr(self) -> (crate::common::v5::AddressType, u16) {
        (crate::common::v5::AddressType::DomainName(self.0), self.1)
    }
}

impl IntoSocksAddr for (&str, u16) {
    fn into_socks_addr(self) -> (crate::common::v5::AddressType, u16) {
        (
            crate::common::v5::AddressType::DomainName(self.0.into()),
            self.1,
        )
    }
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self::new_with_version(stream, Version::Socks5)
    }

    pub fn new_with_version(stream: S, version: Version) -> Self {
        Self { stream, version }
    }

    async fn connect_v4(mut self, addr: impl IntoSocksAddr) -> io::Result<S> {
        use crate::v4::*;

        let (addr, port) = addr.into_socks_addr();
        let addr: AddressType = addr.try_into()?;

        let mut buffer = Vec::new();
        let req = Request {
            command: Command::Connect,
            addr,
            port,
            secret: None,
        };
        req.encode_into(&mut buffer);
        log::trace!("Sending {req:?}");
        self.stream.write_all(&buffer[..]).await?;

        buffer.clear();
        let n = self.stream.read_buf(&mut buffer).await?;
        let (_, response) =
            Response::decode::<nom::error::VerboseError<_>>(&buffer[..n]).map_err(map_nom_error)?;
        log::trace!("Received {response:?}");

        if response.status == Status::Success {
            Ok(self.stream)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("{s:?}", s = response.status),
            ))
        }
    }

    async fn connect_v5(mut self, addr: impl IntoSocksAddr) -> io::Result<S> {
        use crate::v5::*;

        let mut buffer = Vec::new();
        let hello = Hello {
            methods: vec![AuthenticationMethod::None],
        };
        hello.encode_into(&mut buffer);
        log::trace!("Sending {hello:?}");
        self.stream.write_all(&buffer[..]).await?;

        let n = self.stream.read_buf(&mut buffer).await?;
        let (_, hello_response) =
            HelloResponse::decode::<nom::error::VerboseError<_>>(&buffer[..n])
                .map_err(map_nom_error)?;
        log::trace!("Received {hello_response:?}");

        match hello_response.method {
            AuthenticationMethod::None => {}
            // TODO: handle username/password authentication?
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Does not support any authentication method",
                ))
            }
        }

        let (addr, port) = addr.into_socks_addr();
        buffer.clear();
        let req = Request {
            command: Command::Connect,
            addr,
            port,
        };
        req.encode_into(&mut buffer);
        log::trace!("Sending {req:?}");
        self.stream.write_all(&buffer[..]).await?;

        let n = self.stream.read_buf(&mut buffer).await?;
        let (_, response) =
            Response::decode::<nom::error::VerboseError<_>>(&buffer[..n]).map_err(map_nom_error)?;
        log::trace!("Received {response:?}");

        if response.status == Status::Success {
            Ok(self.stream)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("{s:?}", s = response.status),
            ))
        }
    }

    pub async fn connect(self, addr: impl IntoSocksAddr) -> io::Result<S> {
        match self.version {
            Version::Socks4 => self.connect_v4(addr).await,
            Version::Socks5 => self.connect_v5(addr).await,
        }
    }
}
