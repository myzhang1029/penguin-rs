//! SOCKS4/a server helpers.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::net::Ipv4Addr;

use super::Error;
use bytes::Bytes;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

/// Read a SOCKS4/a request from the given reader. Returns the command, address, and port.
/// Writes an `Address type not supported` response to the given writer if the address type is not
/// valid. We expect the version byte to have already been read.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
pub async fn read_request<R>(mut reader: R) -> Result<(u8, Bytes, u16), Error>
where
    R: AsyncBufRead + Unpin,
{
    let command = reader
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read command", e))?;
    let rport = reader
        .read_u16()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read port", e))?;
    let ip = reader
        .read_u32()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read ip", e))?;
    let mut user_id = Vec::new();
    reader
        .read_until(0, &mut user_id)
        .await
        .map_err(|e| Error::ProcessSocksRequest("read user id", e))?;
    // Remove the null byte
    user_id.pop();
    trace!("User ID: {:?}", user_id);
    let rhost = if ip >> 24 == 0 {
        let mut domain = Vec::new();
        reader
            .read_until(0, &mut domain)
            .await
            .map_err(|e| Error::ProcessSocksRequest("read domain", e))?;
        // Remove the null byte
        domain.pop();
        Bytes::from(domain)
    } else {
        Ipv4Addr::from(ip).to_string().into()
    };
    Ok((command, rhost, rport))
}

/// Write a SOCKS4/a response to the given writer.
///
/// # Errors
/// Underlying I/O error with a description of the context.
#[inline]
pub async fn write_response<W>(mut writer: W, response: u8) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_u8(0)
        .await
        .map_err(|e| Error::ProcessSocksRequest("write null byte", e))?;
    writer
        .write_u8(response)
        .await
        .map_err(|e| Error::ProcessSocksRequest("write response", e))?;
    writer
        .write_u16(0)
        .await
        .map_err(|e| Error::ProcessSocksRequest("write port", e))?;
    writer
        .write_u32(0)
        .await
        .map_err(|e| Error::ProcessSocksRequest("write ip", e))?;
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
    async fn test_read_request_ip() {
        tracing_subscriber::fmt().try_init().ok();
        let mut reader = Cursor::new([0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x61, 0x00]);
        let (command, rhost, rport) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(rhost, "127.0.0.1");
        assert_eq!(rport, 0x50);
    }

    #[tokio::test]
    async fn test_read_request_domain() {
        tracing_subscriber::fmt().try_init().ok();
        let mut reader = Cursor::new([
            0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x77, 0x77, 0x77, 0x2e, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00,
        ]);
        let (command, rhost, rport) = read_request(&mut reader).await.unwrap();
        assert_eq!(command, 0x01);
        assert_eq!(rhost, "www.example.com");
        assert_eq!(rport, 0x50);
    }

    #[tokio::test]
    async fn test_write_response() {
        tracing_subscriber::fmt().try_init().ok();
        let mut writer = Cursor::new(Vec::new());
        write_response(&mut writer, 0x5a).await.unwrap();
        assert_eq!(
            writer.get_ref(),
            &[0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }
}
