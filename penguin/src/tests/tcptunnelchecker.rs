//! TCP tunnel checker based on vi/tcptunnelchecker by Vitaly Shukela.
//
// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Vitaly Shukela
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

use super::{make_client_args, make_server_args, setup_logging};
use crate::arg::{self, ClientArgs};
use crate::arg::{Remote, default_host};
use crate::client::{HandlerResources, client_main_inner};
use crate::server::{State, run_listener};
use std::io::{self, ErrorKind, Read, Write};
use std::mem::MaybeUninit;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::info;

const LOCALHOST: &str = default_host!([local]);

fn make_tunnel(
    target: SocketAddr,
) -> (
    SocketAddr,
    thread::JoinHandle<()>,
    thread::JoinHandle<()>,
    watch::Sender<bool>,
) {
    let server_listener = TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    server_listener.set_nonblocking(true).unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let (should_stop_tx, mut should_stop_rx) = watch::channel(false);
    let mut s_should_stop_rx = should_stop_rx.clone();
    let server_worker = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let state = State::new().await.unwrap();
            let server_listener = tokio::net::TcpListener::from_std(server_listener).unwrap();
            tokio::select! {
                _ = s_should_stop_rx.changed() => (),
                _ = run_listener(server_listener, None, state) => unreachable!(),
            }
        });
    });
    thread::sleep(Duration::from_millis(100));
    // Ignoring race conditions here
    let tmp1 = TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    let fwd_listen = tmp1.local_addr().unwrap();
    let remote = Remote::from_str(&format!("{fwd_listen}:{target}")).unwrap();
    let ca = make_client_args(LOCALHOST, server_addr.port(), vec![remote]);
    let (hr, stream_command_rx, datagram_rx) = HandlerResources::create();
    let client_worker = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let args_static = Box::leak(Box::new(ca));
            let hr_static = Box::leak(Box::new(hr));
            drop(tmp1);
            tokio::select! {
                _ = should_stop_rx.changed() => (),
                r = client_main_inner(args_static, hr_static, stream_command_rx, datagram_rx) => panic!("Client main returned: {r:?}"),
            }
        });
    });
    thread::sleep(Duration::from_millis(100));
    (fwd_listen, server_worker, client_worker, should_stop_tx)
}

/// Write as much data as possible to this nonblocking writer
fn clog<W: Write>(mut s: W) -> io::Result<usize> {
    let buf = [0u8; 1024];
    let mut writelen = 1024;
    let mut waitctr = 6;
    let mut written = 0;
    loop {
        match s.write(&buf[0..writelen]) {
            Ok(0) => break Err(ErrorKind::WriteZero.into()),
            Ok(x) => written += x,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if waitctr > 0 {
                    thread::sleep(Duration::from_millis(25));
                    waitctr -= 1;
                    continue;
                } else if writelen > 1 {
                    writelen = 1;
                    continue;
                }
                break Ok(written);
            }
            Err(e) => {
                if e.kind() != ErrorKind::Interrupted {
                    break Err(e);
                }
            }
        }
    }
}

#[test]
fn test_inner() {
    setup_logging();
    let listener = TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    let laddr = listener.local_addr().unwrap();
    let (taddr, s_worker, c_worker, should_stop_tx) = make_tunnel(laddr);

    let listen_thread = thread::spawn(move || {
        let incoming_side = listener.accept().unwrap().0;
        drop(listener);
        incoming_side.set_nonblocking(true).unwrap();
        incoming_side.shutdown(Shutdown::Write).unwrap();
        info!("`incoming_side` socket shutdown_wr");
        incoming_side
    });
    let mut outgoing_side = TcpStream::connect(taddr).unwrap();
    outgoing_side.set_nonblocking(true).unwrap();
    let sz = clog(&mut outgoing_side).unwrap();
    info!("clogged `outgoing_side` socket, size: {sz}");
    let incoming_side = listen_thread.join().unwrap();
    // Now both `cs` and `cc` sockets are fully clogged. Let's close one of them and see what happens to the other one.
    thread::sleep(Duration::from_millis(100));
    drop(incoming_side);
    let s = outgoing_side;

    // Check if the other end can detect the closure of the socket
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() <= deadline,
            "The other end did not detect socket closure in time"
        );
        let mut buf = [0u8; 256];
        let r = s.peek(&mut buf).and_then(|_| s.take_error());
        if let Ok(Some(e)) | Err(e) = r {
            if [
                ErrorKind::BrokenPipe,
                ErrorKind::ConnectionAborted,
                ErrorKind::ConnectionReset,
            ]
            .contains(&e.kind())
            {
                break;
            }
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            if e.kind() != ErrorKind::WouldBlock {
                panic!("Socket error: {e:?}");
            }
        }
        thread::sleep(Duration::from_millis(50))
    }
    should_stop_tx.send(true).unwrap();
    s_worker.join().unwrap();
    c_worker.join().unwrap();
}
