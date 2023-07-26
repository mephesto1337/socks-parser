use std::io;

use socks_parser::{ConnectionRequest, Destination, Server};
use tokio::net::{TcpListener, TcpStream};

async fn hanle_request(c: ConnectionRequest) -> io::Result<(TcpStream, Destination)> {
    let stream = match &c.destination.addr {
        socks_parser::v5::AddressType::IPv4(ip4) => {
            TcpStream::connect((*ip4, c.destination.port)).await?
        }
        socks_parser::v5::AddressType::DomainName(n) => {
            TcpStream::connect((n.as_str(), c.destination.port)).await?
        }
        socks_parser::v5::AddressType::IPv6(ip6) => {
            TcpStream::connect((*ip6, c.destination.port)).await?
        }
    };

    let addr = stream.peer_addr()?;
    log::info!(
        "{req}:{port} -> {res}:{port}",
        req = c.destination.addr,
        res = addr.ip(),
        port = addr.port(),
    );
    Ok((stream, addr.into()))
}

async fn handle_stream(mut local: TcpStream, mut remote: TcpStream) -> io::Result<()> {
    tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let local_addr = listener.local_addr()?;
    log::info!("Listening on {local_addr}");
    let server = Server::new(listener);
    server.run(hanle_request, handle_stream).await?;

    Ok(())
}
