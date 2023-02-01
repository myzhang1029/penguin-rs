#!/bin/bash

set -o pipefail

# Start the tunnels
(ulimit -n 32; cargo run -- -qq server) &
PID_SERVER=$!
(ulimit -n 32; cargo run -- client 'ws://localhost:8080/ws' '5201:127.0.0.1:1234/tcp') &
PID_CLIENT=$!

python << 'EOF' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 1234))
s.listen()
while True:
    conn, addr = s.accept()
    conn.sendall(b"Good.")
    conn.close()
EOF
PID_PYTHON=$!
trap 'kill $PID_SERVER; kill $PID_CLIENT; kill $PID_PYTHON; true' EXIT

sleep 3

exit_status=0

# Run the tests

# forwarding with an active target
if ~/go/bin/tcpgoon run 127.0.0.1 5201 -yc 512
then
    echo "tcpgoon passed"
else
    echo "tcpgoon failed"
    exit_status=1
fi

kill $PID_PYTHON

# forwarding with an inactive target
if ~/go/bin/tcpgoon run 127.0.0.1 5201 -yc 512
then
    echo "tcpgoon passed"
else
    echo "tcpgoon failed"
    exit_status=1
fi

#if ! tcptunnelchecker '127.0.0.1:1234' '127.0.0.1:5201' | grep 'FAIL'
#then
#    echo "tcptunnelchecker passed"
#else
#    echo "tcptunnelchecker failed"
#    exit_status=1
#fi

exit $exit_status