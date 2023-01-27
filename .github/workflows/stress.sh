#!/bin/bash

set -o pipefail

# Start the tunnels
cargo run -- -qq server &
PID_SERVER=$!
cargo run -- -qq client 'ws://localhost:8080/ws' '5201:127.0.0.1:1234/tcp' &
PID_CLIENT=$!

trap "kill $PID_SERVER; kill $PID_CLIENT" EXIT

sleep 3

# Run the tests
if ! tcptunnelchecker '127.0.0.1:1234' '127.0.0.1:5201' | grep 'FAIL'
then
    echo "tcptunnelchecker passed"
else
    echo "tcptunnelchecker failed"
fi

if ~/go/bin/tcpgoon run 127.0.0.1 5201 -yc 2560
then
    echo "tcpgoon passed"
else
    echo "tcpgoon failed"
    exit 1
fi
