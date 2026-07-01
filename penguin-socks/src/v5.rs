//! SOCKS5 server helpers (RFC 1928).
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::{Error, magics};
use bytes::{Buf, Bytes};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read SOCKS authentication methods from the given reader.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
pub async fn read_auth_methods<R>(reader: &mut R) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let num_methods = reader
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read number of methods", e))?;
    let mut methods = vec![0; usize::from(num_methods)];
    reader
        .read_exact(&mut methods)
        .await
        .map_err(|e| Error::ProcessSocksRequest("read methods", e))?;
    Ok(methods)
}

/// Write a SOCKS5 authentication method selection to the given writer.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
pub async fn write_auth_method<W>(writer: &mut W, method: u8) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[magics::VER_5, method])
        .await
        .map_err(|e| Error::ProcessSocksRequest("write auth method", e))?;
    writer
        .flush()
        .await
        .map_err(|e| Error::ProcessSocksRequest("flush", e))?;
    Ok(())
}

/// Read a SOCKS5 request from the given reader. Returns the command, address, and port.
/// Writes an `Address type not supported` response to the given writer if the address type is not
/// valid.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
pub async fn read_request<RW>(stream: &mut RW) -> Result<(u8, Vec<u8>, u16), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read version", e))?;
    if version != magics::VER_5 {
        return Err(Error::SocksVersion(version));
    }
    let command = stream
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read command", e))?;
    let _reserved = stream
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read reserved", e))?;
    let address = read_address(stream).await?;
    let port = stream
        .read_u16()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read port", e))?;
    Ok((command, address, port))
}

/// Read a SOCKS5 address from the given reader.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
async fn read_address<RW>(stream: &mut RW) -> Result<Vec<u8>, Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let address_type = stream
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read address type", e))?;
    match address_type {
        magics::ATYP_IPV4 => {
            // IPv4
            let mut addr = [0; 4];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Error::ProcessSocksRequest("read address", e))?;
            Ok(Ipv4Addr::from(addr).to_string().into())
        }
        magics::ATYP_DOMAIN => {
            // Domain name
            let len = stream
                .read_u8()
                .await
                .map_err(|e| Error::ProcessSocksRequest("read domain length", e))?;
            let mut addr = vec![0; usize::from(len)];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Error::ProcessSocksRequest("read domain address", e))?;
            Ok(addr)
        }
        magics::ATYP_IPV6 => {
            // IPv6
            let mut addr = [0; 16];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Error::ProcessSocksRequest("read address", e))?;
            Ok(Ipv6Addr::from(addr).to_string().into())
        }
        _ => {
            // Unsupported address type
            stream
                .write_all(&[
                    magics::VER_5,
                    magics::REP_ATYPUNSUP,
                    magics::RESERVED,
                    magics::ATYP_IPV4,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ])
                .await
                .map_err(|e| Error::ProcessSocksRequest("write unsupported address type", e))?;
            stream
                .flush()
                .await
                .map_err(|e| Error::ProcessSocksRequest("flush", e))?;
            Err(Error::AddressType(address_type))
        }
    }
}

/// Write a SOCKS5 response to the given writer.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
pub async fn write_response<W>(writer: &mut W, response: u8, local: SocketAddr) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = match local {
        SocketAddr::V4(addr) => {
            // 4 bytes header + 4 bytes address + 2 bytes port
            let total_len = 4 + 4 + 2;
            let mut buf = vec![0; total_len];
            buf[3] = magics::ATYP_IPV4;
            buf[4..8].copy_from_slice(&addr.ip().octets());
            buf
        }
        SocketAddr::V6(addr) => {
            // 4 bytes header + 16 bytes address + 2 bytes port
            let total_len = 4 + 16 + 2;
            let mut buf = vec![0; total_len];
            buf[3] = magics::ATYP_IPV6;
            buf[4..20].copy_from_slice(&addr.ip().octets());
            buf
        }
    };
    buf[0] = magics::VER_5;
    buf[1] = response; // response code
    buf[2] = magics::RESERVED; // reserved
    let port = local.port();
    let len = buf.len();
    buf[len - 2..len].copy_from_slice(&port.to_be_bytes());
    writer
        .write_all(&buf)
        .await
        .map_err(|e| Error::ProcessSocksRequest("write response", e))?;
    writer
        .flush()
        .await
        .map_err(|e| Error::ProcessSocksRequest("flush", e))?;
    Ok(())
}

/// Write a failed response with an unspecified BIND address.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
pub async fn write_response_unspecified<W>(writer: &mut W, response: u8) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[
            magics::VER_5,
            response,
            magics::RESERVED,
            magics::ATYP_IPV4,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ])
        .await
        .map_err(|e| Error::ProcessSocksRequest("write response", e))?;
    writer
        .flush()
        .await
        .map_err(|e| Error::ProcessSocksRequest("flush", e))?;
    Ok(())
}

/// Parse a UDP relay request.
///
/// # Returns
/// Returns a tuple of (destination address, destination port, remaining data).
///
/// # Errors
/// Returns
/// - `Error::ParseAssociate` if the request cannot be parsed.
/// - `Error::FragmentedUdp` if the request is a fragmented UDP packet.
/// - `Error::UnknownAddressType` if the request has an unknown address type.
pub fn parse_udp_relay_header(mut buf: Bytes) -> Result<(Bytes, u16, Bytes), Error> {
    if buf.remaining() < 4 {
        return Err(Error::ParseAssociate);
    }
    let _reserved = buf.get_u16();
    let frag = buf.get_u8();
    if frag != 0 {
        return Err(Error::FragmentedUdp);
    }
    let atyp = buf.get_u8();
    let (dst, port) = match atyp {
        magics::ATYP_IPV4 => {
            // IPv4
            if buf.remaining() < 6 {
                return Err(Error::ParseAssociate);
            }
            let addr = buf.get_u32();
            let dst = Ipv4Addr::from(addr).to_string();
            let port = buf.get_u16();
            (dst.into(), port)
        }
        magics::ATYP_DOMAIN => {
            // Domain name
            if buf.remaining() < 1 {
                return Err(Error::ParseAssociate);
            }
            let len = usize::from(buf.get_u8());
            if buf.remaining() < len + 2 {
                return Err(Error::ParseAssociate);
            }
            let dst = buf.split_to(len);
            let port = buf.get_u16();
            (dst, port)
        }
        magics::ATYP_IPV6 => {
            // IPv6
            if buf.remaining() < 18 {
                return Err(Error::ParseAssociate);
            }
            let addr = buf.get_u128();
            let dst = Ipv6Addr::from(addr).to_string();
            let port = buf.get_u16();
            (dst.into(), port)
        }
        y => return Err(Error::UnknownAddressType(y)),
    };
    Ok((dst, port, buf))
}

/// Prepare a UDP relay response to `target` with the given `data`.
#[inline]
#[must_use]
pub fn udp_relay_response(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    // Write the header
    let mut content = vec![0; 3];
    match target.ip() {
        IpAddr::V4(ip) => {
            content.extend(ip.octets());
            content.extend([magics::ATYP_IPV4]);
        }
        IpAddr::V6(ip) => {
            content.extend(ip.octets());
            content.extend([magics::ATYP_IPV6]);
        }
    }
    content.extend(&target.port().to_be_bytes());
    content.extend(data);
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_auth_methods() {
        let mut reader = Cursor::new(vec![0x02, 0x00, 0x01]);
        let methods = read_auth_methods(&mut reader).await.unwrap();
        assert_eq!(methods, vec![0x00, 0x01]);
    }

    #[tokio::test]
    async fn test_write_auth_method() {
        let mut writer = Cursor::new(vec![]);
        write_auth_method(&mut writer, 0x00).await.unwrap();
        assert_eq!(writer.get_ref(), &[0x05, 0x00]);
    }

    #[tokio::test]
    async fn test_read_request_v4() {
        let mut reader = Cursor::new(vec![
            0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50,
        ]);
        let (command, address, port) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(address, "127.0.0.1".as_bytes());
        assert_eq!(port, 0x50);
    }

    #[tokio::test]
    async fn test_read_request_v6() {
        let mut reader = Cursor::new(vec![
            0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x50,
        ]);
        let (command, address, port) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(address, "2001:db8::1".as_bytes());
        assert_eq!(port, 0x50);
    }

    #[tokio::test]
    async fn test_read_request_domain() {
        let mut reader = Cursor::new(vec![
            0x05, 0x01, 0x00, 0x03, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x50,
        ]);
        let (command, address, port) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(address, "www.example.com".as_bytes());
        assert_eq!(port, 0x50);
    }

    #[tokio::test]
    async fn test_read_request_invalid_address_type() {
        let mut reader = Cursor::new(vec![0x05, 0x01, 0x00, 0x02, 0x00, 0x50]);
        read_request(&mut reader).await.unwrap_err();
    }

    #[tokio::test]
    async fn test_write_response() {
        let mut writer = Cursor::new(vec![]);
        write_response(&mut writer, 0x00, ([127, 0, 0, 1], 80).into())
            .await
            .unwrap();
        assert_eq!(
            writer.get_ref(),
            &[0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50]
        );
    }

    #[tokio::test]
    async fn test_write_response_unspecified() {
        let mut writer = Cursor::new(vec![]);
        write_response_unspecified(&mut writer, 0x00).await.unwrap();
        assert_eq!(
            writer.get_ref(),
            &[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }
}
