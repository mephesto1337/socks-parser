use std::{future::Future, io};

use crate::{ConnectionRequest, Destination, Version, Wire};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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

    pub async fn run<HC, HS, S, FC, FS>(
        self,
        handle_request: HC,
        handle_stream: HS,
    ) -> io::Result<()>
    where
        HC: FnOnce(ConnectionRequest) -> FC + Send + Clone + 'static,
        HS: FnOnce(TcpStream, S) -> FS + Send + Clone + 'static,
        FC: Future<Output = io::Result<(S, Destination)>> + Send,
        FS: Future<Output = io::Result<()>> + Send,
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            log::info!("New connection from {addr}");
            let hc = handle_request.clone();
            let hs = handle_stream.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, hc, hs).await {
                    log::error!("Issue with client {addr}: {e}");
                }
            });
        }
    }

    async fn handle_client<HC, HS, S, FC, FS>(
        mut stream: TcpStream,
        handle_request: HC,
        handle_stream: HS,
    ) -> io::Result<()>
    where
        HC: FnOnce(ConnectionRequest) -> FC,
        HS: FnOnce(TcpStream, S) -> FS,
        FC: Future<Output = io::Result<(S, Destination)>>,
        FS: Future<Output = io::Result<()>>,
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buffer = Vec::with_capacity(512);

        let n = stream.read_buf(&mut buffer).await?;

        let (_, version) = Version::decode(&buffer[..n]).map_err(map_nom_error)?;

        let remote_stream = match version {
            Version::Socks4 => Self::handle_client_v4(&mut stream, buffer, handle_request).await?,
            Version::Socks5 => Self::handle_client_v5(&mut stream, buffer, handle_request).await?,
        };

        handle_stream(stream, remote_stream).await
    }

    async fn handle_client_v4<HC, S, FC>(
        stream: &mut TcpStream,
        mut buffer: Vec<u8>,
        handle_request: HC,
    ) -> io::Result<S>
    where
        HC: FnOnce(ConnectionRequest) -> FC,
        FC: Future<Output = io::Result<(S, Destination)>>,
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use crate::v4::*;

        let (_, req) = Request::decode(&buffer).map_err(map_nom_error)?;

        let connection_request = (req.addr.clone(), req.port).into();
        match handle_request(connection_request).await {
            Ok((s, destination)) => {
                let response = Response {
                    status: Status::Success,
                    addr: match destination.addr {
                        crate::common::v5::AddressType::IPv4(ip4) => ip4,
                        _ => 0u32.into(),
                    },
                    port: destination.port,
                };
                buffer.clear();
                response.encode_into(&mut buffer);
                stream.write_all(&buffer[..]).await?;
                Ok(s)
            }
            Err(e) => {
                let response = Response {
                    status: Status::Rejected,
                    addr: match req.addr {
                        AddressType::IPv4(ip4) => ip4,
                        _ => 0u32.into(),
                    },
                    port: req.port,
                };
                buffer.clear();
                response.encode_into(&mut buffer);
                stream.write_all(&buffer[..]).await?;
                Err(e)
            }
        }
    }

    async fn handle_client_v5<HC, S, FC>(
        stream: &mut TcpStream,
        mut buffer: Vec<u8>,
        handle_request: HC,
    ) -> io::Result<S>
    where
        HC: FnOnce(ConnectionRequest) -> FC,
        FC: Future<Output = io::Result<(S, Destination)>>,
        S: AsyncRead + AsyncWrite + Unpin,
    {
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

        let connection_request = (req.addr.clone(), req.port).into();
        match handle_request(connection_request).await {
            Ok((s, destination)) => {
                let response = Response {
                    status: Status::Success,
                    addr: destination.addr,
                    port: destination.port,
                };
                buffer.clear();
                response.encode_into(&mut buffer);
                stream.write_all(&buffer[..]).await?;
                Ok(s)
            }
            Err(e) => {
                let response = Response {
                    status: Status::GeneralFailure,
                    addr: req.addr,
                    port: req.port,
                };
                buffer.clear();
                response.encode_into(&mut buffer);
                stream.write_all(&buffer[..]).await?;
                Err(e)
            }
        }
    }
}
