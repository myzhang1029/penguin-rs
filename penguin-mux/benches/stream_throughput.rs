use bytes::Bytes;
use divan::{Bencher, counter::BytesCount};
use penguin_mux::{Multiplexor, config::Options, ws::WebSocket};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::hint::black_box;
use std::sync::LazyLock;
#[cfg(feature = "tungstenite")]
use tokio::io::DuplexStream;
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
        .worker_threads(2)
        .build()
        .unwrap()
});

const EACH_WRITE_SIZE: usize = 32768;
#[cfg(debug_assertions)]
const SLOW_NUMS: &[usize] = &[1, 16, 64];
#[cfg(not(debug_assertions))]
const SLOW_NUMS: &[usize] = &[1, 32, 256, 2048, 4096];
#[cfg(debug_assertions)]
const FAST_NUMS: &[usize] = &[2, 32, 128];
#[cfg(not(debug_assertions))]
const FAST_NUMS: &[usize] = &[2, 64, 512, 4096, 8192];

#[inline]
fn make_payload() -> Bytes {
    let mut rng = SmallRng::seed_from_u64(0xabcd);
    let mut payload = vec![0u8; EACH_WRITE_SIZE];
    rng.fill_bytes(&mut payload);
    let payload = Bytes::from(payload);
    payload
}

#[inline]
async fn make_connected_tcp_stream() -> (TcpStream, TcpStream) {
    let s_socket = TcpListener::bind(("::1", 0)).await.unwrap();
    let s_addr = s_socket.local_addr().unwrap();
    let server_task = tokio::spawn(async move { s_socket.accept().await.unwrap().0 });
    let client = TcpStream::connect(s_addr).await.unwrap();
    let server = server_task.await.unwrap();
    (client, server)
}

trait BenchConstructableWebSocket: WebSocket + Sized {
    type PeerType: WebSocket;
    async fn get_pair() -> (Self, Self::PeerType);
}

#[cfg(feature = "tungstenite")]
impl BenchConstructableWebSocket for WebSocketStream<TcpStream> {
    type PeerType = WebSocketStream<TcpStream>;
    #[inline]
    async fn get_pair() -> (Self, Self::PeerType) {
        let (client, server) = make_connected_tcp_stream().await;
        let server_task =
            tokio::spawn(WebSocketStream::from_raw_socket(server, Role::Server, None));
        let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let server = server_task.await.unwrap();
        (client, server)
    }
}

#[cfg(feature = "tungstenite")]
#[derive(Debug)]
struct DuplexWebSocketStream<const BUF_SIZE: usize>(WebSocketStream<DuplexStream>);

#[cfg(feature = "tungstenite")]
impl<const BUF_SIZE: usize> WebSocket for DuplexWebSocketStream<BUF_SIZE> {
    #[inline(always)]
    fn poll_next_unpin(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<penguin_mux::ws::Message, penguin_mux::Error>>> {
        self.0.poll_next_unpin(cx)
    }
    #[inline(always)]
    fn poll_ready_unpin(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), penguin_mux::Error>> {
        self.0.poll_ready_unpin(cx)
    }
    #[inline(always)]
    fn start_send_unpin(
        &mut self,
        item: penguin_mux::ws::Message,
    ) -> Result<(), penguin_mux::Error> {
        self.0.start_send_unpin(item)
    }
    #[inline(always)]
    fn poll_flush_unpin(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), penguin_mux::Error>> {
        self.0.poll_flush_unpin(cx)
    }
    #[inline(always)]
    fn poll_close_unpin(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), penguin_mux::Error>> {
        self.0.poll_close_unpin(cx)
    }
}

#[cfg(feature = "tungstenite")]
impl<const BUF_SIZE: usize> BenchConstructableWebSocket for DuplexWebSocketStream<BUF_SIZE> {
    type PeerType = Self;
    #[inline]
    async fn get_pair() -> (Self, Self::PeerType) {
        let (client, server) = tokio::io::duplex(BUF_SIZE);
        let server_task =
            tokio::spawn(WebSocketStream::from_raw_socket(server, Role::Server, None));
        let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let server = server_task.await.unwrap();
        (Self(client), Self(server))
    }
}

#[cfg(feature = "yawc")]
impl BenchConstructableWebSocket for yawc::WebSocket<TcpStream> {
    type PeerType = yawc::WebSocket<yawc::HttpStream>;
    #[inline]
    async fn get_pair() -> (Self, Self::PeerType) {
        let (client, server) = make_connected_tcp_stream().await;
        let s_addr = server.local_addr().unwrap();
        let (job_tx, mut job_rx) = tokio::sync::mpsc::channel(2);
        let server_fn = move |req: hyper::Request<hyper::body::Incoming>| {
            let job_tx = job_tx.clone();
            async move {
                let (response, fut) =
                    yawc::WebSocket::upgrade_with_options(req, yawc::Options::default())?;
                let task = tokio::task::spawn(async move { fut.await.unwrap() });
                job_tx.send(task).await.unwrap();
                yawc::Result::Ok(response)
            }
        };
        let server_task = tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(server);
            let conn_fut = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper::service::service_fn(server_fn))
                .with_upgrades();
            conn_fut.await.unwrap();
        });
        let url = format!("ws://{s_addr}").parse().unwrap();
        let client = yawc::WebSocket::handshake(url, client, yawc::Options::default().with_utf8())
            .await
            .unwrap();
        server_task.await.unwrap();
        let Some(result) = job_rx.recv().await else {
            panic!("Server task did not send a result");
        };
        assert!(job_rx.is_empty(), "Server task sent more than one result");
        let server = result.await.unwrap();
        (client, server)
    }
}

#[inline]
async fn make_connected_mux<WS: BenchConstructableWebSocket>()
-> (Multiplexor<SmallRng>, Multiplexor<SmallRng>) {
    let (client, server) = WS::get_pair().await;
    let server_task = tokio::spawn(async move {
        let rng = SmallRng::seed_from_u64(0x1234);
        let (server, task) =
            Multiplexor::new_detailed::<_, std::time::Instant>(server, Options::default(), rng);
        task.spawn(None);
        server
    });
    let rng = SmallRng::seed_from_u64(0xabcd);
    let (client, task) =
        Multiplexor::new_detailed::<_, std::time::Instant>(client, Options::default(), rng);
    task.spawn(None);
    let server = server_task.await.unwrap();
    (client, server)
}

#[cfg_attr(all(feature = "tungstenite", feature = "yawc"), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>, yawc::WebSocket<TcpStream>],
))]
#[cfg_attr(all(feature = "tungstenite", not(feature = "yawc")), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>],
))]
#[cfg_attr(all(not(feature = "tungstenite"), feature = "yawc"), divan::bench(
    types = [yawc::WebSocket<TcpStream>],
))]
fn bench00_baseline_ws<WS: BenchConstructableWebSocket>(b: Bencher<'_, '_>) {
    b.with_inputs(|| {
        TOKIO_RT.block_on(async { (make_payload(), make_connected_mux::<WS>().await) })
    })
    .bench_values(|(_, (client, server))| {
        TOKIO_RT.block_on(async {
            let server_task = tokio::spawn(async move {
                let mut stream = server.accept_stream_channel().await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut stream = client.new_stream_channel(&[], 0).await.unwrap();
            stream.shutdown().await.unwrap();
            server_task.await.unwrap();
        });
    });
}

#[divan::bench(args = FAST_NUMS)]
fn bench01_baseline_tcp(b: Bencher<'_, '_>, num_writes: usize) {
    b.with_inputs(|| {
        TOKIO_RT.block_on(async { (make_payload(), make_connected_tcp_stream().await) })
    })
    .counter(BytesCount::new(num_writes * EACH_WRITE_SIZE))
    .bench_values(|(payload, (mut client, mut server))| {
        TOKIO_RT.block_on(async {
            let len = payload.len();
            let server_task = tokio::spawn(async move {
                server.shutdown().await.unwrap();
                let mut buf = vec![0; len];
                for _ in 0..num_writes {
                    server.read_exact(&mut buf).await.unwrap();
                    black_box(&buf);
                }
            });
            for _ in 0..num_writes {
                client.write_all(&payload).await.unwrap();
            }
            client.shutdown().await.unwrap();
            server_task.await.unwrap();
        });
    });
}

#[divan::bench(args = SLOW_NUMS)]
fn bench02_baseline_tcp_bidir(b: Bencher<'_, '_>, num_writes: usize) {
    b.with_inputs(|| {
        TOKIO_RT.block_on(async { (make_payload(), make_connected_tcp_stream().await) })
    })
    .counter(BytesCount::new(num_writes * EACH_WRITE_SIZE * 2))
    .bench_values(|(payload, (mut client, mut server))| {
        TOKIO_RT.block_on(async {
            let len = payload.len();
            let server_task = tokio::spawn(async move {
                let mut buf = vec![0; len];
                for _ in 0..num_writes {
                    server.write_all(&payload).await.unwrap();
                    server.read_exact(&mut buf).await.unwrap();
                    black_box(&buf);
                }
                server.shutdown().await.unwrap();
            });
            let mut buf = vec![0; len];
            for _ in 0..num_writes {
                client.read_exact(&mut buf).await.unwrap();
                client.write_all(&buf).await.unwrap();
            }
            client.shutdown().await.unwrap();
            server_task.await.unwrap();
        });
    });
}

#[cfg_attr(all(feature = "tungstenite", feature = "yawc"), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>, yawc::WebSocket<TcpStream>],
    args = FAST_NUMS,
))]
#[cfg_attr(all(feature = "tungstenite", not(feature = "yawc")), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>],
    args = FAST_NUMS,
))]
#[cfg_attr(all(not(feature = "tungstenite"), feature = "yawc"), divan::bench(
    types = [yawc::WebSocket<TcpStream>],
    args = FAST_NUMS,
))]
fn bench10_stream_throughput<WS: BenchConstructableWebSocket>(b: Bencher<'_, '_>, num_writes: usize) {
    b.with_inputs(|| {
        TOKIO_RT.block_on(async { (make_payload(), make_connected_mux::<WS>().await) })
    })
    .counter(BytesCount::new(num_writes * EACH_WRITE_SIZE))
    .bench_values(|(payload, (client, server))| {
        TOKIO_RT.block_on(async {
            let len = payload.len();
            let server_task = tokio::spawn(async move {
                let mut stream = server.accept_stream_channel().await.unwrap();
                stream.shutdown().await.unwrap();
                let mut buf = vec![0; len];
                for _ in 0..num_writes {
                    stream.read_exact(&mut buf).await.unwrap();
                    black_box(&buf);
                }
            });
            let mut stream = client.new_stream_channel(&[], 0).await.unwrap();
            for _ in 0..num_writes {
                stream.write_all(&payload).await.unwrap();
            }
            stream.shutdown().await.unwrap();
            server_task.await.unwrap();
        });
    });
}

#[cfg_attr(all(feature = "tungstenite", feature = "yawc"), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>, yawc::WebSocket<TcpStream>],
    args = SLOW_NUMS,
))]
#[cfg_attr(all(feature = "tungstenite", not(feature = "yawc")), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>],
    args = SLOW_NUMS,
))]
#[cfg_attr(all(not(feature = "tungstenite"), feature = "yawc"), divan::bench(
    types = [yawc::WebSocket<TcpStream>],
    args = SLOW_NUMS,
))]
fn bench11_stream_throughput_bidir<WS: BenchConstructableWebSocket>(
    b: Bencher<'_, '_>,
    num_writes: usize,
) {
    b.with_inputs(|| {
        TOKIO_RT.block_on(async { (make_payload(), make_connected_mux::<WS>().await) })
    })
    .counter(BytesCount::new(num_writes * EACH_WRITE_SIZE * 2))
    .bench_values(|(payload, (client, server))| {
        TOKIO_RT.block_on(async {
            let len = payload.len();
            let server_task = tokio::spawn(async move {
                let mut stream = server.accept_stream_channel().await.unwrap();
                let mut buf = vec![0; len];
                for _ in 0..num_writes {
                    stream.write_all(&payload).await.unwrap();
                    stream.read_exact(&mut buf).await.unwrap();
                    black_box(&buf);
                }
                stream.shutdown().await.unwrap();
            });
            let mut stream = client.new_stream_channel(&[], 0).await.unwrap();
            let mut buf = vec![0; len];
            for _ in 0..num_writes {
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(&buf).await.unwrap();
            }
            stream.shutdown().await.unwrap();
            server_task.await.unwrap();
        });
    });
}

#[cfg_attr(all(feature = "tungstenite", feature = "yawc"), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>, yawc::WebSocket<TcpStream>],
    args = SLOW_NUMS,
))]
#[cfg_attr(all(feature = "tungstenite", not(feature = "yawc")), divan::bench(
    types = [WebSocketStream<TcpStream>, DuplexWebSocketStream<4096>, DuplexWebSocketStream<1048576>],
    args = SLOW_NUMS,
))]
#[cfg_attr(all(not(feature = "tungstenite"), feature = "yawc"), divan::bench(
    types = [yawc::WebSocket<TcpStream>],
    args = SLOW_NUMS,
))]
fn bench12_stream_throughput_with_contention<WS: BenchConstructableWebSocket>(
    b: Bencher<'_, '_>,
    num_concurrent: usize,
) {
    const EACH_JOB_WRITES: usize = 256;
    b.with_inputs(|| {
        TOKIO_RT.block_on(async { (make_payload(), make_connected_mux::<WS>().await) })
    })
    .counter(BytesCount::new(
        num_concurrent * EACH_WRITE_SIZE * EACH_JOB_WRITES * 2,
    ))
    .bench_values(|(payload, (client, server))| {
        TOKIO_RT.block_on(async {
            let mut jobs = tokio::task::JoinSet::new();
            let len = payload.len();
            jobs.spawn(async move {
                let mut server_jobs = tokio::task::JoinSet::new();
                for _ in 0..num_concurrent {
                    let mut stream = server.accept_stream_channel().await.unwrap();
                    let payload = payload.clone(); // cheap
                    server_jobs.spawn(async move {
                        let mut buf = vec![0; len];
                        for _ in 0..EACH_JOB_WRITES {
                            stream.write_all(&payload).await.unwrap();
                            stream.read_exact(&mut buf).await.unwrap();
                            black_box(&buf);
                        }
                        stream.shutdown().await.unwrap();
                    });
                }
                while let Some(res) = server_jobs.join_next().await {
                    res.unwrap();
                }
            });
            for _ in 0..num_concurrent {
                let mut stream = client.new_stream_channel(&[], 0).await.unwrap();
                jobs.spawn(async move {
                    let mut buf = vec![0; len];
                    for _ in 0..EACH_JOB_WRITES {
                        stream.read_exact(&mut buf).await.unwrap();
                        stream.write_all(&buf).await.unwrap();
                    }
                    stream.shutdown().await.unwrap();
                });
            }
            while let Some(res) = jobs.join_next().await {
                res.unwrap();
            }
        });
    });
}

fn main() {
    setup_logging();
    divan::main();
}
