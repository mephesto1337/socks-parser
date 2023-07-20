use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use crate::{Version, Wire};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn map_nom_error(e: nom::Err<nom::error::VerboseError<&[u8]>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e:x?}"))
}

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub fn new(listener: TcpListener) -> Self {
        Self { listener }
    }

    pub async fn run(self) -> io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            log::info!("New connection from {addr}");
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream).await {
                    log::error!("Issue with client {addr}: {e}");
                }
            });
        }
    }

    async fn handle_client(mut stream: TcpStream) -> io::Result<()> {
        let mut buffer = Vec::with_capacity(512);

        let n = stream.read_buf(&mut buffer).await?;

        let (_, version) = Version::decode(&buffer[..n]).map_err(map_nom_error)?;

        match version {
            Version::Socks4 => Self::handle_client_v4(stream, buffer).await,
            Version::Socks5 => Self::handle_client_v5(stream, buffer).await,
        }
    }

    async fn handle_client_v4(mut stream: TcpStream, mut buffer: Vec<u8>) -> io::Result<()> {
        use crate::v4::*;

        let (_, req) = Request::decode(&buffer).map_err(map_nom_error)?;
        let connect_result = match req.addr {
            AddressType::IPv4(ip4) => TcpStream::connect((ip4, req.port)).await,
            AddressType::DomainName(ref n) => TcpStream::connect((n.as_str(), req.port)).await,
        };

        let mut s = match connect_result {
            Ok(s) => s,
            Err(e) => {
                let response = Response {
                    status: Status::Rejected,
                    addr: match req.addr {
                        AddressType::IPv4(ip4) => ip4,
                        AddressType::DomainName(_) => Ipv4Addr::new(0, 0, 0, 0),
                    },
                    port: 0,
                };
                buffer.clear();
                response.encode_into(&mut buffer);
                stream.write_all(&buffer[..]).await?;
                return Err(e);
            }
        };

        let default_addr = || SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), req.port);
        let remote_addr = match s.peer_addr() {
            Ok(SocketAddr::V4(s4)) => s4,
            Ok(SocketAddr::V6(_)) => default_addr(),
            Err(_) => match req.addr {
                AddressType::IPv4(ip4) => SocketAddrV4::new(ip4, req.port),
                AddressType::DomainName(_) => default_addr(),
            },
        };
        let response = Response {
            status: Status::Success,
            addr: *remote_addr.ip(),
            port: remote_addr.port(),
        };
        buffer.clear();
        response.encode_into(&mut buffer);
        stream.write_all(&buffer[..]).await?;
        drop(buffer);

        tokio::io::copy_bidirectional(&mut stream, &mut s).await?;

        Ok(())
    }

    async fn handle_client_v5(mut stream: TcpStream, mut buffer: Vec<u8>) -> io::Result<()> {
        use crate::v5::*;

        let (_, hello) = Hello::decode(&buffer).map_err(map_nom_error)?;
        let method = if hello.methods.contains(&AuthenticationMethod::None) {
            AuthenticationMethod::None
        } else {
            AuthenticationMethod::NotAcceptable
        };

        let response = HelloResponse { method };
        buffer.clear();
        response.encode_into(&mut buffer);
        stream.write_all(&buffer[..]).await?;

        if response.method == AuthenticationMethod::NotAcceptable {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Client requested only unsupported authentication methods",
            ));
        }

        buffer.clear();
        let n = stream.read_buf(&mut buffer).await?;
        let (_, req) = Request::decode(&buffer[..n]).map_err(map_nom_error)?;

        let connect_result = match req.addr {
            AddressType::IPv4(ip4) => TcpStream::connect((ip4, req.port)).await,
            AddressType::DomainName(ref n) => TcpStream::connect((n.as_str(), req.port)).await,
            AddressType::IPv6(ip6) => TcpStream::connect((ip6, req.port)).await,
        };

        let mut s = match connect_result {
            Ok(s) => s,
            Err(e) => {
                let response = Response {
                    status: Status::GeneralFailure,
                    addr: req.addr,
                    port: req.port,
                };
                buffer.clear();
                response.encode_into(&mut buffer);
                stream.write_all(&buffer[..]).await?;
                return Err(e);
            }
        };

        let (addr, port) = match s.peer_addr() {
            Ok(SocketAddr::V4(s4)) => (AddressType::IPv4(*s4.ip()), s4.port()),
            Ok(SocketAddr::V6(s6)) => (AddressType::IPv6(*s6.ip()), s6.port()),
            Err(_) => (req.addr, req.port),
        };
        let response = Response {
            status: Status::Success,
            addr,
            port,
        };
        buffer.clear();
        response.encode_into(&mut buffer);
        stream.write_all(&buffer[..]).await?;
        drop(buffer);

        tokio::io::copy_bidirectional(&mut stream, &mut s).await?;

        Ok(())
    }
}
