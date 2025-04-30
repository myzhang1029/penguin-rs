#![no_main]

use bytes::{Buf, Bytes};
use libfuzzer_sys::fuzz_target;
use penguin_mux::{Datagram, Multiplexor, timing::OptionalDuration};
use tokio::{io::AsyncWriteExt, runtime};
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

fuzz_target!(|data: &[u8]| {
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let data = data.to_vec();
        let (alice, mut eve) = tokio::io::duplex(1024);
        let ws = WebSocketStream::from_raw_socket(alice, Role::Server, None).await;
        let mux = Multiplexor::new(ws, OptionalDuration::NONE, false, None);
        eve.write_all(&data).await.unwrap();
        let flow_id = <Vec<u8> as AsRef<[u8]>>::as_ref(&data)
            .try_get_u32()
            .unwrap_or(0);
        let target_host = data.get(4..251).unwrap_or(&[]).to_vec().into();
        let target_port = <Vec<u8> as AsRef<[u8]>>::as_ref(&data)
            .try_get_u16()
            .unwrap_or(0);
        let data = Bytes::from(data);
        mux.send_datagram(Datagram {
            flow_id,
            target_host,
            target_port,
            data,
        })
        .await
        .unwrap();
    });
});
