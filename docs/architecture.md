# Architecture

OCT has four processes:

1. **Relay** (`oct relay`) — a public or private WebSocket router. It pairs one
   host and one client in a room and forwards opaque messages. It has no
   endpoint keys and does not parse application frames.
2. **Host agent** (`oct host`) — runs next to OpenCode, dials outbound to the
   relay, terminates the endpoint Noise session, and proxies requests to one
   fixed loopback OpenCode origin.
3. **Client gateway** (`oct tui` starts it) — binds an authenticated loopback
   HTTP/WebSocket gateway and dials outbound to the relay. OpenCode's TUI treats
   it as its server.
4. **OpenCode TUI** — the unmodified `opencode --server http://127.0.0.1:<port>`
   process launched by `oct tui`.

## Connection flow

```text
client                         relay                         host
  |                              |                             |
  |-- outbound WSS ------------->|                             |
  |-- RelayControl::Hello ------>|                             |
  |<-- Ready --------------------|                             |
  |                              |<----------- outbound WSS ---|
  |<-- PeerJoined ---------------|----------- PeerJoined ----->|
  |                              |                             |
  |==== Noise XX handshake (end-to-end) ======================>|
  |==== encrypted device/invite prelude ======================>|
  |<=== authenticated host response ===========================|
  |==== encrypted OCT mux (HTTP/SSE/WS/PTY) =================>|
```

The relay only sees WSS frames. With E2EE enabled, every binary OCT frame is a
Noise transport ciphertext. Text relay control messages remain outside Noise.

## Streams

- HTTP requests/responses use `OPEN_HTTP`, `HTTP_RESPONSE`, `DATA`, `END` and
  `RESET`.
- SSE is ordinary streaming `DATA`; OCT does not replay missed events.
- PTY and other WebSocket routes use `OPEN_WS`, fragmented `WS_MESSAGE` and
  `WS_CLOSE`. Binary frames are preserved byte-for-byte.
- `WINDOW_UPDATE` provides 256 KiB per-stream and 8 MiB per-connection byte
  credit.
- A fresh Noise handshake and epoch are created on every reconnect.

## Trust boundaries

| Component | Trust |
|---|---|
| Relay | Untrusted for confidentiality/integrity; trusted for routing and availability |
| Host machine | Trusted; can execute OpenCode tools and access provider credentials |
| Client machine | Trusted paired device |
| Local gateway | Authenticated loopback boundary; never public |
| OpenCode upstream | Fixed loopback origin, never selected from request payload |

The relay can observe IPs, room IDs, timing and ciphertext sizes. It can drop,
delay or close connections. It cannot forge a Noise-authenticated frame or
silently replace the pinned host identity.

## Reliability

- Bounded queues and byte-credit flow control.
- Carrier idle detection with nested PING/PONG.
- Automatic Noise transport rekeying.
- Reconnect with jittered backoff; one host and one client per room.
- Revocation closes the active host connection and rejects future handshakes.

See [protocol.md](protocol.md) for wire details.
