use bytes::Bytes;
use divan::Bencher;
use penguin_mux::Dupe;
use std::sync::LazyLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime,
};

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
fn baseline(b: Bencher) {
    b.with_inputs(make_payload)
    .bench_values(|_| {
        TOKIO_RT.block_on(async {
            let s_socket = TcpListener::bind(("::1", 0)).await.unwrap();
            let s_addr = s_socket.local_addr().unwrap();
            tokio::spawn(async move {
                let mut s_stream = s_socket.accept().await.unwrap().0;
                s_stream.shutdown().await.unwrap();
            });
            let mut c_stream = TcpStream::connect(s_addr).await.unwrap();
            c_stream.shutdown().await.unwrap();
        });
    });
}

#[divan::bench(args = [1, 2, 4, 8, 16, 32, 64, 128, 256])]
fn stream_throughput(b: Bencher, num_writes: usize) {
    b.with_inputs(make_payload)
    .bench_values(|payload| {
        TOKIO_RT.block_on(async {
            let s_socket = TcpListener::bind(("::1", 0)).await.unwrap();
            let s_addr = s_socket.local_addr().unwrap();
            let s_payload = payload.dupe();
            tokio::spawn(async move {
                let mut s_stream = s_socket.accept().await.unwrap().0;
                for _ in 0..num_writes {
                    s_stream.write_all(&s_payload).await.unwrap();
                }
                s_stream.shutdown().await.unwrap();
                let mut buf = vec![0; s_payload.len()];
                for _ in 0..num_writes {
                    s_stream.read_exact(&mut buf).await.unwrap();
                }
                assert_eq!(buf, s_payload);
            });
            let mut c_stream = TcpStream::connect(s_addr).await.unwrap();
            for _ in 0..num_writes {
                c_stream.write_all(&payload).await.unwrap();
            }
            c_stream.shutdown().await.unwrap();
            let mut buf = vec![0; payload.len()];
            for _ in 0..num_writes {
                c_stream.read_exact(&mut buf).await.unwrap();
            }
            assert_eq!(buf, payload);
        });
    });
}

fn main() {
    divan::main();
}
