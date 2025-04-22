use bytes::Bytes;
use divan::{Bencher, counter::BytesCount};
use penguin_mux::{Dupe, Multiplexor, timing::OptionalDuration};
use std::sync::LazyLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime,
};
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

static TOKIO_RT: LazyLock<runtime::Runtime> = LazyLock::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

const EACH_WRITE_SIZE: usize = 4096;

fn make_payload() -> Bytes {
    (0..EACH_WRITE_SIZE).map(|_| rand::random::<u8>()).collect()
}

#[divan::bench]
fn baseline_ws(b: Bencher<'_, '_>) {
    b.with_inputs(make_payload).bench_values(|_| {
        TOKIO_RT.block_on(async {
            let s_socket = TcpListener::bind(("::1", 0)).await.unwrap();
            let s_addr = s_socket.local_addr().unwrap();
            tokio::spawn(async move {
                let tcpstream = s_socket.accept().await.unwrap().0;
                let server = WebSocketStream::from_raw_socket(tcpstream, Role::Server, None).await;
                let mux = Multiplexor::new(server, OptionalDuration::NONE, false, None);
                let mut stream = mux.accept_stream_channel().await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let tcpstream = TcpStream::connect(s_addr).await.unwrap();
            let client = WebSocketStream::from_raw_socket(tcpstream, Role::Client, None).await;
            let mux = Multiplexor::new(client, OptionalDuration::NONE, false, None);
            let mut stream = mux.new_stream_channel(&[], 0).await.unwrap();
            stream.shutdown().await.unwrap();
        });
    });
}

#[divan::bench(args = [1, 8, 64, 512, 4096, 32768])]
fn baseline_tcp(b: Bencher<'_, '_>, num_writes: usize) {
    b.with_inputs(make_payload)
        .counter(BytesCount::new(num_writes * EACH_WRITE_SIZE))
        .bench_values(|payload| {
            TOKIO_RT.block_on(async {
                let s_socket = TcpListener::bind(("::1", 0)).await.unwrap();
                let s_addr = s_socket.local_addr().unwrap();
                let s_payload = payload.dupe();
                tokio::spawn(async move {
                    let mut stream = s_socket.accept().await.unwrap().0;
                    for _ in 0..num_writes {
                        stream.write_all(&s_payload).await.unwrap();
                    }
                    stream.shutdown().await.unwrap();
                });
                let mut stream = TcpStream::connect(s_addr).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut buf = vec![0; payload.len()];
                for _ in 0..num_writes {
                    stream.read_exact(&mut buf).await.unwrap();
                }
                assert_eq!(buf, payload);
            });
        });
}

#[divan::bench(args = [1, 8, 64, 512, 4096, 32768])]
fn bench_stream_throughput(b: Bencher<'_, '_>, num_writes: usize) {
    b.with_inputs(make_payload)
        .counter(BytesCount::new(num_writes * EACH_WRITE_SIZE))
        .bench_values(|payload| {
            TOKIO_RT.block_on(async {
                let s_socket = TcpListener::bind(("::1", 0)).await.unwrap();
                let s_addr = s_socket.local_addr().unwrap();
                let s_payload = payload.dupe();
                tokio::spawn(async move {
                    let tcpstream = s_socket.accept().await.unwrap().0;
                    let server =
                        WebSocketStream::from_raw_socket(tcpstream, Role::Server, None).await;
                    let mux = Multiplexor::new(server, OptionalDuration::NONE, false, None);
                    let mut stream = mux.accept_stream_channel().await.unwrap();
                    for _ in 0..num_writes {
                        stream.write_all(&s_payload).await.unwrap();
                    }
                    stream.shutdown().await.unwrap();
                });
                let tcpstream = TcpStream::connect(s_addr).await.unwrap();
                let client = WebSocketStream::from_raw_socket(tcpstream, Role::Client, None).await;
                let mux = Multiplexor::new(client, OptionalDuration::NONE, false, None);
                let mut stream = mux.new_stream_channel(&[], 0).await.unwrap();
                stream.shutdown().await.unwrap();
                //tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let mut buf = vec![0; payload.len()];
                for _ in 0..num_writes {
                    stream.read_exact(&mut buf).await.unwrap();
                    // No check for correctness as this should be guaranteed by tests
                }
            });
        });
}

fn main() {
    setup_logging();
    divan::main();
}
