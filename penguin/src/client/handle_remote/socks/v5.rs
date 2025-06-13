//! SOCKS5 server helpers (RFC 1928).
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

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
        .write_all(&[0x05, method])
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
pub async fn read_request<RW>(stream: &mut RW) -> Result<(u8, Bytes, u16), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read version", e))?;
    if version != 0x05 {
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
async fn read_address<RW>(stream: &mut RW) -> Result<Bytes, Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let address_type = stream
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read address type", e))?;
    trace!("address type: {address_type}");
    match address_type {
        0x01 => {
            // IPv4
            let mut addr = [0; 4];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Error::ProcessSocksRequest("read address", e))?;
            Ok(Ipv4Addr::from(addr).to_string().into())
        }
        0x03 => {
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
            Ok(Bytes::from(addr))
        }
        0x04 => {
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
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
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
            buf[3] = 0x01; // address type
            buf[4..8].copy_from_slice(&addr.ip().octets());
            buf
        }
        SocketAddr::V6(addr) => {
            // 4 bytes header + 16 bytes address + 2 bytes port
            let total_len = 4 + 16 + 2;
            let mut buf = vec![0; total_len];
            buf[3] = 0x04; // address type
            buf[4..20].copy_from_slice(&addr.ip().octets());
            buf
        }
    };
    buf[0] = 0x05; // version
    buf[1] = response; // response code
    buf[2] = 0x00; // reserved
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
            0x05, response, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .await
        .map_err(|e| Error::ProcessSocksRequest("write response", e))?;
    writer
        .flush()
        .await
        .map_err(|e| Error::ProcessSocksRequest("flush", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_auth_methods() {
        crate::tests::setup_logging();
        let mut reader = Cursor::new(vec![0x02, 0x00, 0x01]);
        let methods = read_auth_methods(&mut reader).await.unwrap();
        assert_eq!(methods, vec![0x00, 0x01]);
    }

    #[tokio::test]
    async fn test_write_auth_method() {
        crate::tests::setup_logging();
        let mut writer = Cursor::new(vec![]);
        write_auth_method(&mut writer, 0x00).await.unwrap();
        assert_eq!(writer.get_ref(), &[0x05, 0x00]);
    }

    #[tokio::test]
    async fn test_read_request_v4() {
        crate::tests::setup_logging();
        let mut reader = Cursor::new(vec![
            0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50,
        ]);
        let (command, address, port) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(address, "127.0.0.1");
        assert_eq!(port, 0x50);
    }

    #[tokio::test]
    async fn test_read_request_v6() {
        crate::tests::setup_logging();
        let mut reader = Cursor::new(vec![
            0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x50,
        ]);
        let (command, address, port) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(address, "2001:db8::1");
        assert_eq!(port, 0x50);
    }

    #[tokio::test]
    async fn test_read_request_domain() {
        crate::tests::setup_logging();
        let mut reader = Cursor::new(vec![
            0x05, 0x01, 0x00, 0x03, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x50,
        ]);
        let (command, address, port) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(address, "www.example.com");
        assert_eq!(port, 0x50);
    }

    #[tokio::test]
    async fn test_read_request_invalid_address_type() {
        crate::tests::setup_logging();
        let mut reader = Cursor::new(vec![0x05, 0x01, 0x00, 0x02, 0x00, 0x50]);
        read_request(&mut reader).await.unwrap_err();
    }

    #[tokio::test]
    async fn test_write_response() {
        crate::tests::setup_logging();
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
        crate::tests::setup_logging();
        let mut writer = Cursor::new(vec![]);
        write_response_unspecified(&mut writer, 0x00).await.unwrap();
        assert_eq!(
            writer.get_ref(),
            &[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }
}
