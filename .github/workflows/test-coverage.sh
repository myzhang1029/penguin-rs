#!/bin/bash -veu

TLS=$1
CONFIG_NAME=$2
VERBOSE=${3:---verbose}
export RUSTFLAGS="-Cinstrument-coverage"

# Run async-acceptor tests only
cargo nextest run --all-targets "$VERBOSE" --package async-acceptor

# Run cow-bytes tests only
cargo nextest run --all-targets "$VERBOSE" --package cow-bytes
# Run no_std cow-bytes tests only
cargo nextest run --all-targets "$VERBOSE" --package cow-bytes --no-default-features

# Run penguin-socks tests only
cargo nextest run --all-targets "$VERBOSE" --package penguin-socks

# Run penguin-mux tests with minimal features
cargo nextest run --all-targets "$VERBOSE" --no-default-features --package penguin-mux

# Note that tokio/rt is always on in penguin-mux tests

# Run penguin-mux tests with tokio-io-util support
cargo nextest run --all-targets "$VERBOSE" --no-default-features --package penguin-mux --features tokio-io-util

# Run cargo penguin-mux tests with tokio-time support
cargo nextest run --all-targets "$VERBOSE" --no-default-features --package penguin-mux --features tokio-time

# Run cargo penguin-mux tests with tungstenite (essentially all features)
cargo nextest run --all-targets "$VERBOSE" --no-default-features --package penguin-mux --features std,tokio,tungstenite



# Run cargo tests with more features on
cargo nextest run --all-targets "$VERBOSE" --features "$TLS",ring,tests-real-internet4,tests-acme-has-pebble,penguin-binary,acme,default-is-ipv6,tokio-console,deadlock-detection --no-default-features

# Run cargo tests with default features
case "$CONFIG_NAME" in
  *linux-gnu)
    printf '[target.%s]\nrunner="sudo -E"' "$(rustc -vV | sed -n 's,host: ,,p')" > ~/.cargo/config.toml
    cargo nextest run --all-targets "$VERBOSE" --features "$TLS",ring,tests-real-internet4,acme,penguin-binary,tproxy --no-default-features
    rm ~/.cargo/config.toml
    ;;
  *)
    cargo nextest run --all-targets "$VERBOSE" --features "$TLS",ring,tests-real-internet4,acme,penguin-binary,tproxy --no-default-features
    ;;
esac

# Run cargo tests with the nohash hashmap
cargo nextest run --all-targets "$VERBOSE" --features "$TLS",ring,tests-real-internet4,acme,penguin-binary,nohash --no-default-features

# Run cargo tests with PENGUIN_TLS_CHROMIUM_LIKE enabled
if [ "$TLS" != "nativetls" ]; then
  PENGUIN_TLS_CHROMIUM_LIKE=on cargo nextest run --all-targets "$VERBOSE" --features "$TLS",ring,tests-real-internet4,acme,penguin-binary --no-default-features
fi


# Process coverage data
grcov . --binary-path ./target/debug/ -s . -t lcov --branch --ignore-not-existing --ignore "/*" -o debug.info
find . -name "*.profraw" -type f -delete


# Run cargo penguin-mux tests with loom
if [ "$CONFIG_NAME" != "aarch64-pc-windows-msvc" ]; then
  RUSTFLAGS="--cfg loom -Cinstrument-coverage" LOOM_LOG=debug cargo nextest run --lib --release --no-default-features --package penguin-mux --features std,tokio

  # Process coverage data for loom tests
  grcov . --binary-path ./target/release/ -s . -t lcov --branch --ignore-not-existing --ignore "/*" -o release.info
fi
