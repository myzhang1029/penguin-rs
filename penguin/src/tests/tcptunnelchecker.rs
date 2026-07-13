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
use std::cell::{Cell, RefCell, UnsafeCell};
use std::fmt::Display;
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

static BACKEND_SUPPORT_HTTP2: OnceLock<bool> = OnceLock::new();
const LOCALHOST: &str = default_host!([local]);

fn make_tunnel(
    target: SocketAddr,
) -> (
    SocketAddr,
    thread::JoinHandle<()>,
    thread::JoinHandle<()>,
    watch::Sender<bool>,
) {
    BACKEND_SUPPORT_HTTP2.get_or_init(|| false);
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
            let state = State::new(&BACKEND_SUPPORT_HTTP2).await.unwrap();
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
    let mut written: usize = 0;
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

/// Read and ignore all the data in a separate thread
fn drain<R: Read + Send + 'static>(mut s: R, close_notification: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(_x) => (),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => (),
                Err(_e) => break,
            }
        }
        close_notification.store(true, Ordering::SeqCst);
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseDetectMode {
    CloseIncomingCheckOutgoing,
    CloseOutgoingCheckIncoming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WritingPolicy {
    Ignore,
    Shutdown,
    Clog,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadingPolicy {
    Ignore,
    Drain,
}

/// Clog both directions of the tunnel by writing, but not reading the data.
/// Then close of of the sockets. Will RST propagate to the other end?
fn test_inner(
    mode: CloseDetectMode,
    outgoing_write: WritingPolicy,
    outgoing_read: ReadingPolicy,
    incoming_write: WritingPolicy,
    incoming_read: ReadingPolicy,
) {
    if (incoming_read, outgoing_write) == (ReadingPolicy::Drain, WritingPolicy::Clog) {
        return;
    }
    if (outgoing_read, incoming_write) == (ReadingPolicy::Drain, WritingPolicy::Clog) {
        return;
    }
    if mode == CloseDetectMode::CloseIncomingCheckOutgoing
        && !matches!(
            (outgoing_write, outgoing_read),
            (WritingPolicy::Clog, _) | (_, ReadingPolicy::Drain)
        )
    {
        return;
    }
    if mode == CloseDetectMode::CloseOutgoingCheckIncoming
        && !matches!(
            (incoming_write, incoming_read),
            (WritingPolicy::Clog, _) | (_, ReadingPolicy::Drain)
        )
    {
        return;
    }

    setup_logging();
    let listener = TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    let laddr = listener.local_addr().unwrap();
    let (taddr, s_worker, c_worker, should_stop_tx) = make_tunnel(laddr);

    let listen_thread = thread::spawn(move || {
        let mut incoming_side: TcpStream = listener.accept().unwrap().0;
        drop(listener);
        incoming_side.set_nonblocking(true).unwrap();
        let cn = match incoming_read {
            ReadingPolicy::Ignore => None,
            ReadingPolicy::Drain => {
                let cn = Arc::new(AtomicBool::new(true));
                drain(incoming_side.try_clone().unwrap(), cn.clone());
                Some(cn)
            }
        };
        match incoming_write {
            WritingPolicy::Ignore => (),
            WritingPolicy::Shutdown => {
                incoming_side.shutdown(Shutdown::Write).unwrap();
                info!("`incoming_side` socket shutdown_wr");
            }
            WritingPolicy::Clog => {
                let sz = clog(&mut incoming_side).unwrap();
                info!("clogged `incoming_side` socket, size: {sz}");
            }
        }
        // thread::sleep(Duration::from_millis(500));
        (incoming_side, cn)
    });
    let mut outgoing_side = TcpStream::connect(taddr).unwrap();
    outgoing_side.set_nonblocking(true).unwrap();
    let cs_close = match outgoing_read {
        ReadingPolicy::Ignore => None,
        ReadingPolicy::Drain => {
            let cs_close = Arc::new(AtomicBool::new(true));
            drain(outgoing_side.try_clone().unwrap(), cs_close.clone());
            Some(cs_close)
        }
    };
    match outgoing_write {
        WritingPolicy::Ignore => (),
        WritingPolicy::Shutdown => {
            outgoing_side.shutdown(Shutdown::Write).unwrap();
            info!("`outgoing_side` socket shutdown_wr");
        }
        WritingPolicy::Clog => {
            let sz = clog(&mut outgoing_side).unwrap();
            info!("clogged `outgoing_side` socket, size: {sz}");
        }
    }
    let (incoming_side, cc_close) = listen_thread.join().unwrap();
    // Now both `cs` and `cc` sockets are fully clogged. Let's close one of them and see what happens to the other one.
    thread::sleep(Duration::from_millis(100));
    let (s, closenotif) = match mode {
        CloseDetectMode::CloseIncomingCheckOutgoing => {
            drop(incoming_side);
            (outgoing_side, cs_close)
        }
        CloseDetectMode::CloseOutgoingCheckIncoming => {
            drop(outgoing_side);
            (incoming_side, cc_close)
        }
    };

    // Check if the other end can detect the closure of the socket
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() <= deadline,
            "The other end did not detect socket closure in time"
        );
        if let Some(acn) = closenotif.as_ref()
            && acn.load(Ordering::SeqCst)
        {
            break;
        }
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

macro_rules! expand_tests {
    ($m:expr, $ow:expr, $or:expr, $iw:expr, $ir:expr, $oid:ident, $iid:ident) => {
        paste::paste! {
            #[test]
            #[expect(non_snake_case)]
            #[ignore]
            fn [<out $oid _in $iid>] () {
                test_inner($m, $ow, $or, $iw, $ir);
            }
        }
    };
    ($m:expr, $ow:expr, $or:expr, $ir:expr, $oid:ident, $iid:ident) => {
        paste::paste! {
            expand_tests! { $m, $ow, $or, WritingPolicy::Ignore, $ir, $oid, $iid }
            expand_tests! { $m, $ow, $or, WritingPolicy::Clog, $ir, $oid, [<Clog $iid>] }
            expand_tests! { $m, $ow, $or, WritingPolicy::Shutdown, $ir, $oid, [<Shut $iid>] }
        }
    };
    ($m:expr, $ow:expr, $or:expr, $oid:ident, $iid:ident) => {
        paste::paste! {
            expand_tests! { $m, $ow, $or, ReadingPolicy::Ignore, $oid, $iid }
            expand_tests! { $m, $ow, $or, ReadingPolicy::Drain, $oid, [<Drain $iid>] }
        }
    };
    ($m:expr, $or:expr, $oid:ident, $iid:ident) => {
        paste::paste! {
            expand_tests! { $m, WritingPolicy::Ignore, $or, $oid, $iid }
            expand_tests! { $m, WritingPolicy::Clog, $or, [<Clog $oid>], $iid }
            expand_tests! { $m, WritingPolicy::Shutdown, $or, [<Shut $oid>], $iid }
        }
    };
    ($m:expr, $oid:ident, $iid:ident) => {
        paste::paste! {
            expand_tests! { $m, ReadingPolicy::Ignore, $oid, $iid }
            expand_tests! { $m, ReadingPolicy::Drain, [<Drain $oid>], $iid }
        }
    };
}

expand_tests! { CloseDetectMode::CloseIncomingCheckOutgoing, Check, Close }
expand_tests! { CloseDetectMode::CloseOutgoingCheckIncoming, Close, Check }
