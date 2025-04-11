# Penguin IP over WebSocket Protocol

## Introduction
This document describes the protocol used by Rusty Penguin to tunnel
the Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) over
HTTP WebSocket.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Protocol Version
The current protocol version is `penguin-v7`.

## Function Specification
### Service Architecture
Penguin follows the client-server model. The client initiates connections to
the server, and, in general, directs what happens on the connection.

Since Penguin is based on Hypertext Transfer Protocol (HTTP) WebSocket, the
server MUST be a conforming HTTP and WebSocket server. However, it is OPTIONAL
for the client to be interoperable with a non-Penguin HTTP server.

### Connection Establishment
The client initiates a connection with a standard HTTP WebSocket handshake. In
addition to the standard HTTP WebSocket headers, the client MUST send a
`Sec-WebSocket-Protocol` header with the value of the current protocol version
(`penguin-v7`). The server MUST NOT complete the WebSocket upgrade if the
`Sec-WebSocket-Protocol` header is missing or the value is not a version the
server supports. The server MUST send a `Sec-WebSocket-Protocol` header with
the accepted protocol version in the Switching Protocols response.

The client MAY present a pre-shared key (PSK) to the server. The PSK is sent in
the `X-Penguin-PSK` header. The server MAY use the PSK to authenticate the
client, in which case the server MUST NOT complete the WebSocket upgrade if the
PSK is missing or the value is not a PSK the server supports. If the server
does not support or does not require PSK, it MUST ignore any `X-Penguin-PSK`
header. The PSK MAY contain any value allowed as an HTTP header value.

Implementations MAY support additional means of authentication, such as
certificate-based authentication and HTTP basic authentication. The server MAY
require the client to authenticate using any means it supports and it MAY
reject the connection if the client does not authenticate using any means it
supports.

### Connection Termination
The client and server MAY terminate the connection at any time by sending a
WebSocket close frame.

### Data Framing
The client and server MAY send data to each other by sending WebSocket binary
frames. The client and server MUST NOT use other WebSocket data frame types.
WebSocket control frames MAY be used as specified in RFC 6455.

The payload of a WebSocket binary frame MUST be a Penguin frame.

Frame Format:
```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |  Op   |              Flow ID (4 bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   continued   |                Data (variable)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Ver: 4 bits, the version of the Penguin protocol. The current version is `0x07`.

- Op: 4 bits, the operation code of the frame.
  - `0x00`: `Connect` frame
  - `0x01`: `Acknowledge` frame
  - `0x02`: `Reset` frame
  - `0x03`: `Finish` frame
  - `0x04`: `Push` frame
  - `0x05`: `Bind` frame
  - `0x06`: `Datagram` frame

- Flow ID: a 32-bit unsigned integer in network byte order uniquely identifying
  the logical stream or datagram. Stream and Bind operations share the same
  flow ID space, while Datagram operations are free to share the same flow ID space
  or use a different flow ID space.

- Data: the payload of the frame, which varies based on the operation code.

#### `Connect` Frame
The `Connect` frame has the following fields:
- `rwnd`: a 32-bit unsigned integer in network byte order representing the
  maximum number of frames the sender can buffer for this logical stream.
- `target_port`: a 16-bit unsigned integer in network byte order.
  For a client-initiated logical TCP stream, this is the target port of the
  TCP forwarding. For a server-initiated logical TCP stream, this is the
  local port of the server where this logical stream is initiated.
- `target_host`: a variable-length UTF-8 string representing the target host
  of the TCP forwarding or the local address.

#### `Acknowledge` Frame
The `Acknowledge` frame has the following fields:
- `psh_recvd_since`/`rwnd`: a 32-bit unsigned integer in network byte order
  representing the number of frames received since the last acknowledgment,
  if the `flow_id` belongs to an established logical TCP stream; or the
  maximum number of frames the receiver of the `Connect` frame can buffer for
  this logical stream.

#### `Reset` Frame
The `Reset` frame has no additional fields.

#### `Finish` Frame
The `Finish` frame has no additional fields.

#### `Push` Frame
The `Push` frame has the following fields:
- `data`: the payload of the frame.

#### `Bind` Frame
The `Bind` frame has the following fields:
- `bind_type`: a 16-bit unsigned integer in network byte order representing
  the type of bind request.
- `target_port`: a 16-bit unsigned integer in network byte order representing
  the local port the server should bind to.
- `target_host`: a variable-length UTF-8 string representing the IP address or
  hostname the server should bind to. Hostname support is optional and
  implementation-defined.

#### `Datagram` Frame
The `Datagram` frame has the following fields:
- `host_len`: a 1-byte unsigned integer representing the length of the
 `target_host` field in octets.
- `target_port`: a 16-bit unsigned integer in network byte order representing
  the target port of the datagram, or the local port of the server to which the
  datagram was sent to.
- `target_host`: a variable-length UTF-8 string representing the target host
  of the datagram, or the local address of the server to which the datagram was
  sent to.
- `data`: the payload of the datagram.

### Data Transfer
The same WebSocket connection is used to tunnel TCP connections and transfer
UDP datagrams.

### Tunneling Operations
#### Logical TCP Streams
A logical TCP stream connection may be established by both the client and the
server.

To establish a forward connection, one end MUST send a stream frame with the
`Connect` operation code and a unique `flow_id`.

Upon receiving the `Connect` frame, the other end MAY reject its peer's choice
of `flow_id` by sending a stream frame with the `Reset` operation code. If the
other end accepts the `Connect` frame, it MUST reply with a stream frame with
the `Acknowledge` operation code. The data of the `Acknowledge` frame MUST be
its `rwnd` value as a 32-bit unsigned integer.

Both ends SHOULD save the `rwnd` value associated with that stream for later
use, in a counter (`psh_recvd_since`).

After the logical stream is established, both ends MAY send data in a frame
with the `Push` operation code, decrementing its `psh_recvd_since` counter by
one for each frame sent. One end MUST NOT send more than the corresponding
`rwnd` frames before receiving an `Acknowledge` frame from the other end.

Either end MAY send a frame with the `Acknowledge` operation code, with which
the sender acknowledges the receipt of a certain number of frames as a 32-bit
unsigned integer in network byte order in the data of the frame. Upon
receiving an `Acknowledge` frame, the receiver MUST increase its corresponding
`psh_recvd_since` counter by the value in the data of the frame.
One end MUST send an `Acknowledge` frame when it processes `rwnd` frames from
the other end after sending the last `Acknowledge` frame.
However, implementations MAY send `Ack` frames more frequently to, for example,
reduce blocking delay in anticipation of frequent writing.

An implementation MAY choose to send `Acknowledge` with a larger `rwnd` value
than what is advertised initially in the `Connect` frame. This allows the
sender to increase the `rwnd` dynamically based on the network conditions and
the receiver's ability to process frames.

Either end MAY send a frame with the `Finish` operation code, with which the
sender indicates that it will not send any more data. When both ends send a
`Finish` frame, the logical stream is closed.

Either end MAY send a frame with the `Reset` operation code, with which the
sender indicates that it either received a frame with an invalid `flow_id` or
an abrupt closure of that logical stream. When either end sends a `Reset`
frame, the logical stream is closed.

Since the underlying WebSocket connection is reliable, there is no need to
acknowledge the receipt of a frame. Therefore, the use of the `Acknowledge`
frame is only for flow control of `Push` frames.

#### Client Forwarding Requests
The client MAY request the server to forward a TCP connection to a specific
host and port by initiating a logical TCP stream with its intended target host
and port in the initial `Connect` frame.

#### Client Bind Requests
The client MAY request the server to listen on a specific port and forward
incoming connections to the client. This is done by sending a stream frame with
the `Bind` operation code. The data of the frame MUST be a 16-bit unsigned
integer in network byte order representing the port number on which the server
should listen for incoming connections and a variable-length UTF-8 string
representing the IP address or hostname the server should bind to.

Upon receiving the `Bind` frame, the server MAY reply with a stream frame with
the `Reset` operation code if it cannot honour the bind request (for example,
if the requested port is already in use, the requested address is invalid, or
the server is not configured to allow bind requests). However, if the bind
request is successfully honoured, the server MUST reply with a stream frame
with the `Finish` operation code.

The `bind_type` field of the `Bind` frame takes two values:
- `1`: TCP socket binding request
- `3`: UDP datagram binding request

For a TCP socket binding request, the `flow_id` is immediately freed once the
Bind request is honoured or rejected. Subsequent communications on the bound
port are established using the procedures for a normal logical TCP stream.

For a UDP datagram binding request, the server MUST keep the `flow_id` of the
`Bind` request as the `flow_id` for future datagram frames sent to the client.
Since UDP is connection-less, this ensures that the client is in control of
the `flow_id` space of datagram frames.

#### UDP Datagram Tunneling
The client and server MAY send UDP datagrams to each other using the `Datagram`
operation code.

For a client-originated datagram, the client SHOULD allocate a unique `flow_id`
for each (source host, source port, target host, target port) tuple it sees,
and the server SHOULD forward the datagram to the target host and port
specified in the `target_host` and `target_port` fields of the datagram frame.
After forwarding the datagram, the server SHOULD wait for a response datagram
from the target host and port for at least five (5) seconds. If the server
receives a response datagram, it SHOULD send a datagram frame with the
`flow_id` field set to the `flow_id` of the original datagram frame, and the
`data` field set to the payload of the response datagram. The value of the
`target_host` and `target_port` fields of the responding datagram frame is
implementation-defined.

The server MUST NOT originate a datagram frame unless the client has sent a
`Bind` request with the `bind_type` set to `3`. The server SHOULD forward all
UDP packets received on the bound port to the client using the `Datagram`
operation code. The `flow_id` of the datagram frame sent to the client MUST
be the same as the `flow_id` of the original `Bind` request. The `target_host`
and `target_port` fields of the datagram frame sent to the client MUST be
the same as the `target_host` and `target_port` fields of the original `Bind`
request. The client MAY wait for a response datagram from the server and send
such a response datagram back to the server using the same `flow_id`. The
`target_host` and `target_port` fields of such a response datagram frame is
implementation-defined.

## Security Considerations
The protocol is designed to be indistinguishable from a normal HTTP traffic
with WebSocket. The server MAY decide to make reasonable efforts to prevent the
detection of the presence of the protocol, for example, by acting as a normal
HTTP server and only upgrading the connection to WebSocket when the client
sends a valid WebSocket handshake request with the correct PSK.

The integrity of the data and confidentiality of the data are to be provided by
the underlying WebSocket connection.
