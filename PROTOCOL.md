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

#### Stream Frame
A stream frame is used to tunnel a TCP stream.

Stream Frame Format:
```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type (1 byte) |  Op (1 byte)  |     Source Port (2 bytes)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Destination Port (2 bytes)  |         Data (variable)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Type: `0x01` for a stream frame.

- Operation code: `0x00` is a `Con` frame, `0x02` is an `Ack` frame,
  `0x03` is a `Rst` frame, `0x04` is a `Fin` frame, `0x05` is a `Psh` frame,
  `0x06` is a `Bnd` frame. `0x01` is reserved for compatibility.

- Source Port: a 16-bit unsigned integer in network byte order chosen by the
  initiator of the stream.

- Destination Port: a 16-bit unsigned integer in network byte order chosen
  by the other end of the stream.

- Data: the payload of the frame.

#### Datagram Frame
A datagram frame is used to forward a UDP datagram.

Datagram Frame Format:
```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type (1 byte) | HLen (1 byte) |     Source Port (2 bytes)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Destination Port (2 bytes)  |    Target Port (2 bytes)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Target Host (variable)     |        Data (variable)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Type: `0x03` for a datagram frame.

- HLen: the length of the `Target Host` field in bytes.

- Source Port: a 16-bit unsigned integer in network byte order chosen by the
  initiator of the datagram.

- Destination Port: a 16-bit unsigned integer in network byte order chosen
  by the other end of the datagram.

- Target Host: the target host of the datagram.

- Target Port: the target port of the datagram. That is, an actual UDP port on
  the target host to which the datagram should be forwarded.

- Data: the payload of the frame.

### Data Transfer
The same WebSocket connection is used to tunnel TCP connections and transfer
UDP datagrams.

#### Logical TCP Stream Tunneling
- **Client-Initiated Logical TCP Streams**:
  A "forward" connection is established by the client to the server.

  To establish a forward connection, the client MUST send a stream frame with
  the `Con` operation code, an unique source port, and a destination port of
  zero (0).

  The data of the frame MUST be a 32-bit unsigned integer in network byte order
  (`rwnd`), a 16-bit unsigned integer in network byte order (`targer_port`),
  and a variable-length UTF-8 string (`targer_host`).

  `rwnd` is the maximum number of frames the client can buffer. `targer_port`
  and `targer_host` are the target port and host of the TCP stream.

  Upon receiving the `Con` frame, the server MUST send a stream frame with the
  `Ack` operation code, the destination port set to the source port of the
  `Con` frame, and the source port set to a unique 16-bit unsigned integer.

  The data of the frame MUST be a 32-bit unsigned integer in network byte order
  representing the maximum number of frames the server can buffer.

  Both ends SHOULD save the `rwnd` value associated with that stream for later
  use.

- **Client Bind Requests**: The client MAY request the server to listen on a
  specific port and forward incoming connections to the client. This is done by
  sending a stream frame with the `Bnd` operation code. The data of the frame
  MUST be a 16-bit unsigned integer in network byte order representing the port
  number on which the server should listen for incoming connections and a
  variable-length UTF-8 string representing the IP address or hostname the
  server should bind to.

  The source port of the `Bnd` frame MUST be a unique 16-bit unsigned integer
  chosen by the client allocated from the same port space as the source ports
  for normal stream frames. The destination port of the `Bnd` frame MUST be set
  to zero (0).

  Upon receiving the `Bnd` frame, the server MAY reply with a stream frame with
  the `Rst` operation code if it cannot honour the bind request (for example,
  if the requested port is already in use, the requested address is invalid, or
  the server is not configured to allow bind requests). However, if the bind
  request is successfully honoured, the server MUST reply with a stream frame
  with the `Fin` operation code. The destination port of the `Fin` frame MUST
  be set to the source port of the `Bnd` frame, and the source port is ignored.

  The source port of the `Bnd` frame is only used for the purpose of the
  request and does not persist beyond the `Bnd` - `Rst`/`Fin` exchange.
  After the completion of the `Bnd` - `Rst`/`Fin` exchange, this port is free
  to be used for other logical TCP streams.

- **Server-Initiated Logical TCP Streams**:
  A server-initiated logical TCP stream is established by the server in
  response to a connection to a port previously established by a client using
  the `Bnd` operation. When the server receives a connection on the bound port,
  it MUST establish a logical TCP stream by sending a stream frame with the
  `Con` operation code. The source port of this `Con` frame MUST be a unique
  16-bit unsigned integer in network byte order chosen by the server, and the
  destination port MUST be set to zero (0). The data of the frame MUST include:
  - A 32-bit unsigned integer in network byte order representing the maximum
    number of frames (`rwnd`) the server can buffer for this logical stream,
  - A 16-bit unsigned integer in network byte order representing the target
    port in the original `Bnd` request, and
  - A variable-length UTF-8 string representing the target host in the original
    `Bnd` request.

  Upon receiving this `Con` frame, the client MUST reply with a stream frame
  with the `Ack` operation code in the same manner as described in the
  "Client-Initiated Logical TCP Streams" section.

- **Logical Stream Operations**:
  After the logical stream is established, the client and server MAY send data
  in a frame with the `Psh` operation code. However, one end MUST NOT send more
  than the corresponding `rwnd` frames before receiving an `Ack` frame from the
  other end.

  Either end MAY send a frame with the `Ack` operation code, with which the
  sender acknowledges the receipt of a certain number of frames as a 32-bit
  unsigned integer in network byte order in the data of the frame. Upon
  receiving an `Ack` frame, the receiver MUST increase its corresponding `rwnd`
  by the value in the data of the frame. One end MUST send an `Ack` frame when
  it processes `rwnd` frames from the other end after sending the last `Ack`
  frame. However, implementations MAY send `Ack` frames more frequently to, for
  example, reduce blocking delay in anticipation of frequent writing.

  An implementation MAY choose to send `Ack` with a larger `rwnd` value than
  what is advertised initially in the `Con` frame. This allows the sender to
  increase the `rwnd` dynamically based on the network conditions and the
  receiver's ability to process frames.

  Either end MAY send a frame with the `Fin` operation code, with which the
  sender indicates that it will not send any more data. When both ends send a
  `Fin` frame, the logical stream is closed.

  Either end MAY send a frame with the `Rst` operation code, with which the
  sender indicates that it either received a frame with an invalid stream ID or
  an abrupt closure of that logical stream. When either end sends a `Rst` frame,
  the logical stream is closed.

  Since the underlying WebSocket connection is reliable, there is no need to
  acknowledge the receipt of a frame. Therefore, the use of the `Ack` frame is
  only for flow control of `Psh` frames.

#### UDP Datagram Forwarding
The client MAY send a datagram frame to forward a UDP datagram. The client
MUST set the `HLen` field to the length of the target host in bytes. The
client MUST set the `Target Host` field to the target host of the datagram.
The client MUST set the `Target Port` field to the target port of the
datagram. The client MUST set the `User ID` field to a 32-bit unsigned
integer in network byte order uniquely identifying the source of the datagram
to be forwarded. The client MUST set the `Data` field to the payload of the
datagram.

The server SHOULD forward the datagram to the target host and port specified
in the `Target Host` and `Target Port` fields. After forwarding the datagram,
the server SHOULD wait for a response datagram from the target host and port
for at least five (5) seconds. If the server receives a response datagram, it
SHOULD send a datagram frame with the `HLen` field set to the length of the
source host in bytes, the `User ID` field set to the `User ID` field of the
original datagram frame, and the `Data` field set to the payload of the
response datagram. The value of the `Target Host` and `Target Port` fields of
the responding datagram frame is implementation-defined.

## Security Considerations
The protocol is designed to be indistinguishable from a normal HTTP traffic
with WebSocket. The server MAY decide to make reasonable efforts to prevent the
detection of the presence of the protocol, for example, by acting as a normal
HTTP server and only upgrading the connection to WebSocket when the client
sends a valid WebSocket handshake request with the correct PSK.

The integrity of the data and confidentiality of the data are to be provided by
the underlying WebSocket connection.
