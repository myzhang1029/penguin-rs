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
Penguin follows the client-server model. The client is the initiator of the
connection, and the server is the responder. Since Penguin is based on
Hypertext Transfer Protocol (HTTP) WebSocket, the server MUST be a conforming
HTTP and WebSocket server. However, it is OPTIONAL for the client to be
interoperable with a non-Penguin HTTP server.

### Connection Establishment
The client initiates a connection with a standard HTTP WebSocket handshake. In
addition to the standard HTTP WebSocket headers, the client MUST send a
`Sec-WebSocket-Protocol` header with the value of the current protocol version
(`penguin-v6`). The server MUST NOT complete the WebSocket upgrade if the
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
| Type (1 byte) |  Op (1 byte)  |      Stream ID (2 bytes)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Data (variable)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Type: `0x01` for a stream frame.

- Stream ID: a 16-bit unsigned integer in network byte order for identifying
  logical streams multiplexed over the same connection.

- Operation code: `0x00` is a `Syn` frame, `0x01` is reserved, `0x02` is an
  `Ack` frame, `0x03` is a `Rst` frame, `0x04` is a `Fin` frame, `0x05` is a
  `Psh` frame, `0x06` is a `Bnd` frame.

- Data: the payload of the frame.

#### Datagram Frame
A datagram frame is used to forward a UDP datagram.

Datagram Frame Format:
```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type (1 byte) | HLen (1 byte) |    Target Host (variable)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Target Port (2 bytes)      |                     User ID
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     (4 bytes)                  |        Data (variable)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Type: `0x03` for a datagram frame.

- HLen: the length of the target host in bytes.

- Target Host: the target host of the datagram.

- Target Port: the target port of the datagram.

- User ID: a 32-bit unsigned integer in network byte order for identifying
  the source of the datagram.

- Data: the payload of the frame.

### Data Transfer
The same WebSocket connection is used to tunnel TCP connections and transfer
UDP datagrams.

#### Logical TCP Stream Tunneling
Logical TCP streams are initiated by the client. The client MUST send a stream
frame with the `Syn` operation code and the stream ID set to a unique 32-bit
unsigned integer in network byte order. The data of the frame MUST be a 32-bit
unsigned integer in network byte order (`rwnd`), a 16-bit unsigned integer in
network byte order (`dest_port`), a variable-length UTF-8 string (`dest_host`).
`rwnd` is the maximum number of frames the client can buffer. `dest_port` and
`dest_host` are the target port and host of the TCP stream.

Upon receiving the `Syn` frame, the server MUST send a stream frame with the
`Syn` operation code containing the same stream ID, The data of the frame MUST
be a 32-bit unsigned integer in network byte order representing the maximum
number of frames the server can buffer. Both ends SHOULD save the `rwnd` value
associated with that stream for later use.

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
