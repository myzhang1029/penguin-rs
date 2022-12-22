//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod parse_remote;
mod ws_connect;

use crate::arg::ClientArgs;
use futures_util::{future, pin_mut, StreamExt};
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::Message;

pub async fn client_main(args: ClientArgs) -> i32 {
    debug!("Client args: {:?}", args);
    let ws_stream = match ws_connect::handshake(&args).await {
        Ok(ws_stream) => ws_stream,
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return 1;
        }
    };

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx));

    let (write, read) = ws_stream.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = {
        read.for_each(|message| async {
            let data = message.unwrap().into_data();
            tokio::io::stdout().write_all(&data).await.unwrap();
        })
    };

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
    0
}

// Our helper method which will read data from stdin and send it along the
// sender provided.
async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>) {
    let mut stdin = tokio::io::stdin();
    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);
        tx.unbounded_send(Message::binary(buf)).unwrap();
    }
}
