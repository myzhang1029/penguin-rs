//! Run a remote TCP connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use crate::client::HandlerResources;
use crate::{
    client::{MuxStream, StreamCommand},
    mux::pipe_streams,
};
use tokio::{
    io::{BufReader, BufWriter},
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use tracing::{error, info, warn};

/// Request a channel from the mux
#[inline]
#[tracing::instrument(skip(stream_command_tx), level = "debug")]
pub(super) async fn request_tcp_channel(
    stream_command_tx: &mpsc::Sender<StreamCommand>,
    dest_host: Vec<u8>,
    dest_port: u16,
) -> Result<MuxStream, Error> {
    let (tx, rx) = oneshot::channel();
    let stream_request = StreamCommand {
        tx,
        host: dest_host,
        port: dest_port,
    };
    stream_command_tx.send(stream_request).await?;
    Ok(rx.await?)
}

/// Handle a TCP Inet->Inet remote.
#[inline]
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_tcp(
    lhost: &str,
    lport: u16,
    rhost: &str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), Error> {
    let listener = TcpListener::bind((lhost, lport)).await?;
    info!("Listening on {lhost}:{lport}");
    loop {
        let (mut tcp_stream, _) = listener.accept().await?;
        // A new channel is created for each incoming TCP connection.
        // It's already TCP, anyways.
        let mut channel = super::complete_or_continue!(
            request_tcp_channel(&handler_resources.stream_command_tx, rhost.into(), rport).await
        );
        tokio::spawn(
            async move { tokio::io::copy_bidirectional(&mut channel, &mut tcp_stream).await },
        );
    }
}

/// Handle a TCP Stdio->Inet remote.
#[tracing::instrument(skip(handler_resources))]
pub(crate) async fn handle_tcp_stdio(
    rhost: &str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), Error> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    // We want `loop` to be able to continue after a connection failure
    loop {
        let channel = super::complete_or_continue!(
            request_tcp_channel(&handler_resources.stream_command_tx, rhost.into(), rport).await
        );
        let (channel_rx, channel_tx) = tokio::io::split(channel);
        let channel_rx = BufReader::new(channel_rx);
        let channel_tx = BufWriter::new(channel_tx);
        super::complete_or_continue_if_retryable!(
            pipe_streams(&mut stdin, &mut stdout, channel_rx, channel_tx).await
        );
    }
}
