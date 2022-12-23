# Rusty Penguin
A fast TCP/UDP tunnel, transported over HTTP WebSockets.
You are right. This project is inspired by jpillora/chisel (and subsequently
my fork myzhang1029/penguin), but completely rewritten in Rust without any
linkage to `chisel`.

Compared to the original `penguin` or `chisel`, this project stripped away
some functionalities:

- There is no internal SSH tunnels because it results in double encapsulation
  when used with HTTPS/WSS.

- There is no user/password authentication because we do not have SSH. Instead,
  use PSK authentication.

- There is no server keep-alive because client keep-alive is enough.

- There is no reverse port forwarding because it is equivalent to spawning
  another server on the client side.

- There is no support to acquire an ACME certificate on-the-fly.

Other than that, this project offers these functionalities compared to
`chisel`:

- Plausible deniability with WebSocket PSK and working `backend`.

- Rust.