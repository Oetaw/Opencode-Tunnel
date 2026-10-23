# OCT/1 protocol specification

**Status:** implementation specification. This document describes the Rust
implementation in `crates/oct-protocol` and the relay/transport
behavior. It is not a claim of production security. The public-deployment gate
is implemented with Noise/E2EE; see [pairing.md](pairing.md) and [security.md](security.md).

Normative words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

## 1. Scope and terminology

OCT carries **semantic OpenCode API operations** — HTTP requests, HTTP
responses, server-sent events, and nested PTY WebSocket messages — between a
local gateway and a remote host. It does **not** carry terminal screens,
keystrokes, or mouse events.

* **Endpoint** — a host agent or a local client gateway.
* **Relay** — an untrusted-for-confidentiality WSS router. It sees room
  metadata, frame sizes, and timing only.
* **Inner frame** — an OCT/1 binary frame defined by this document.
* **Outer relay message** — a text control message or an opaque binary message
  carried by the relay WebSocket.
* **Epoch** — a connection-generation number. A new WSS connection and a new
  Noise handshake produce a new epoch. Stream ids and sequence
  numbers are scoped to one epoch and MUST NOT be reused with stale keys.

## 2. Plaintext loopback mode and E2EE mode

| Property | Legacy loopback mode | E2EE mode (`--e2ee`) |
|---|---|---|
| Carrier | WSS or loopback ws | WSS (TLS) for non-loopback |
| Inner frames | sent directly over binary WSS | Noise XX transport ciphertext |
| Relay visibility | room metadata + opaque binary frames | room metadata + ciphertext |
| Peer authentication | pre-shared room token | pinned host key + device allowlist/invite |
| Deployment | loopback / isolated test only | public relay allowed after security gates |

The legacy mode MUST NOT be deployed on a public relay. In E2EE mode there is
no plaintext fallback: an endpoint that cannot establish a supported Noise
session MUST close the connection, and `HELLO` must negotiate `Feature::E2ee`.

## 3. Connection lifecycle

1. Host and client each open an outbound WSS connection to the relay endpoint
   (`/oct/v1` by default).
2. Each sends a **text** JSON `RelayControl::Hello` as its first message.
3. The relay validates protocol, room, token, and role, then sends
   `RelayControl::Ready`.
4. When both roles are present, the relay sends `PeerJoined { role }` to each
   endpoint. A late joiner is told about the already-present peer.
5. In E2EE mode both endpoints perform a fresh Noise XX handshake over binary
   messages prefixed with `OCTN1`. The client verifies the pinned host static
   key before completing the handshake. An encrypted prelude then carries the
   device name and optional one-time invite; the host authorizes the client
   static key or rejects the connection.
6. Both endpoints construct a mux over the same WebSocket. The first inner
   **binary** frame in each direction is `HELLO`. No other frame is accepted
   before a compatible `HELLO`.
7. Application streams are opened. If the carrier drops, all open streams are
   reset with `UNAVAILABLE`; endpoints reconnect with a fresh noise handshake
   and epoch. There is no in-band stream resume in OCT/1.

## 4. Inner frame format

All integers are big endian. The fixed header is 32 bytes:

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 1 | `version` | MUST be `1` for OCT/1 |
| 1 | 1 | `kind` | See §5 |
| 2 | 2 | `flags` | See §5.1 |
| 4 | 8 | `epoch` | Connection epoch, non-zero recommended; never reused with stale keys |
| 12 | 8 | `stream` | Stream id; 0 is reserved for connection-level frames |
| 20 | 8 | `seq` | Per-stream, per-direction monotonically increasing sequence |
| 28 | 4 | `payload_len` | Unsigned payload length in bytes |
| 32 | `payload_len` | `payload` | Kind-specific |

Hard limits:

* `payload_len` MUST be ≤ **65,536** bytes (64 KiB).
* A complete frame MUST be ≤ **65,568** bytes.
* A decoder MUST reject an oversized length **before** allocating or advancing.
* A frame message with trailing bytes after one complete frame is malformed.
* One WebSocket binary message carries exactly one inner frame.

### 4.1 Example: DATA frame

Frame: version 1, kind DATA (4), flags 0, epoch 7, stream 3, seq 1, payload
`hello`.

```text
01 04 00 00              version, kind, flags
00 00 00 00 00 00 00 07  epoch = 7
00 00 00 00 00 00 00 03  stream = 3
00 00 00 00 00 00 00 01  seq = 1
00 00 00 05              payload length = 5
68 65 6c 6c 6f           "hello"
```

## 5. Frame kinds

| Value | Kind | Direction | Payload |
|---:|---|---|---|
| 1 | `HELLO` | both, first frame | JSON capability object |
| 2 | `OPEN_HTTP` | client → host | encoded HTTP request head |
| 3 | `HTTP_RESPONSE` | host → client | encoded HTTP response head |
| 4 | `DATA` | both | opaque bytes |
| 5 | `END` | both | empty; half-close |
| 6 | `RESET` | both | error code + bounded reason |
| 7 | `OPEN_WS` | client → host | encoded WS upgrade head |
| 8 | `WS_MESSAGE` | both | WS opcode/FIN + bytes |
| 9 | `WS_CLOSE` | both | close code + reason |
| 10 | `WINDOW_UPDATE` | both | `u32` credit |
| 11 | `PING` | both | optional bounded challenge |
| 12 | `PONG` | both | echo of the challenge |
| 13 | `GOAWAY` | both | error code + bounded reason |

`END` MUST have an empty payload in OCT/1 (no trailers). Unknown kinds MUST be
rejected. A future additive kind requires a protocol-minor/feature negotiation.

### 5.1 Flags

| Bit | Name | Meaning |
|---:|---|---|
| `0x0001` | `FLAG_FIN` | Reserved for stream-direction finality |
| `0x0002` | `FLAG_HALF_CLOSE` | Reserved for explicit half-close signalling |
| `0x8000` | `FLAG_CRITICAL` | The frame carries a critical extension |

An endpoint MUST reject a frame when `FLAG_CRITICAL` is set and any unknown
flag bit is also set. Unknown non-critical bits MAY be ignored. Implementations
MUST NOT use flags to bypass the `END`/`RESET` state machine.

## 6. Streams

* Stream id `0` is reserved for connection-level frames (`HELLO`, `PING`,
  `PONG`, `GOAWAY`).
* The **client** allocates odd ids; the **host** allocates even ids.
* An id MUST NOT be reused within one epoch.
* A stream MUST be registered before its `OPEN_*` frame is emitted, and the
  receiver MUST create the stream before dispatching subsequent frames.
* Incoming `OPEN_HTTP`/`OPEN_WS` ids with the wrong parity, zero, duplicate
  registration, or an id already closed in the epoch are protocol errors:
  `RESET(PROTOCOL_ERROR)`. Non-`OPEN` frames reuse the opener's id in both
  directions; the receiver must already have that id registered, and must not
  re-check the sender's parity for response frames.

### 6.1 State machine

```text
             OPEN_HTTP / OPEN_WS
                     |
                   OPEN
                  /    \
        local END      remote HTTP_RESPONSE (client side)
             |                  |
    HALF_CLOSED_LOCAL     HALF_CLOSED_REMOTE
             \                  /
              \                /
                  CLOSED

Any state -- RESET --> RESET (terminal)
```

* The request side sends zero or more `DATA`, then one `END`. After `END` it
  MUST NOT send more request data.
* The response side sends exactly one `HTTP_RESPONSE` (or `RESET`), then zero
  or more `DATA`, then one `END`.
* `OPEN_HTTP` MUST receive exactly one `HTTP_RESPONSE` or `RESET`; a synthetic
  success is forbidden.
* Closing one stream MUST NOT close the carrier or other streams.
* Carrier loss resets every open stream with `UNAVAILABLE`; reconnect is a new
  epoch.
* Sequence numbers MUST increase monotonically per direction. Duplicate or
  out-of-order data is a protocol error and resets the stream.
* Data after `END` or `RESET` in the same direction is a protocol error.

## 7. Payload encodings

All strings are UTF-8 and length-prefixed with `u16` unless stated otherwise.
Header tuples are `(name, value)`. Header names are ASCII letters/digits plus
`-`, `_`, `.`; values MUST NOT contain CR, LF, or NUL.

### 7.1 `HELLO`

Bounded JSON (max 8,192 bytes):

```json
{
  "major": 1,
  "minor": 0,
  "role": "host",
  "features": 6,
  "limits": {
    "max_frame_payload": 65536,
    "max_streams": 128,
    "max_header_bytes": 16384,
    "max_pending_bytes": 8388608
  },
  "opencode_version": "2.0.22",
  "agent": "oct/0.1.0"
}
```

The effective limits are the intersection of both peers' advertised limits.
`major` MUST match exactly. A peer MUST reject a different major version and
MUST NOT fall back to plaintext or an older framing. Feature bits (currently
`1 << discriminant`, with bit 0 unused):

| Bit | Feature | Meaning |
|---:|---|---|
| 1 | `http` | HTTP request/response bridging |
| 2 | `sse` | SSE passes through as DATA |
| 3 | `ws` | Nested PTY WebSocket bridging |
| 4 | `e2ee` | Inner frames are Noise ciphertext; required in E2EE mode |
| 5 | `resync` | Explicit authoritative resync after reconnect |

A feature is usable only if both sides advertise it.

### 7.2 `OPEN_HTTP`

```text
u16 method_len | method
u16 target_len | target
u16 header_count
  repeated: u16 name_len | name | u16 value_len | value
```

Limits: method ≤ 16 bytes, target ≤ 8,192 bytes, header fields ≤ 128,
combined header bytes ≤ 16,384. The target MUST be origin-form: it MUST start
with `/`; `//` and any `scheme://` form are rejected. The method `CONNECT` is
rejected. Absolute-form URLs, authority-form targets, and arbitrary host/port
selection are forbidden: the host dials only its configured fixed loopback
origin.

### 7.3 `HTTP_RESPONSE`

```text
u16 status | u16 header_count | repeated header tuples
```

Status MUST be in `100..=599`. Headers obey the same field/byte limits.

### 7.4 `RESET` and `GOAWAY`

```text
u16 error_code | u16 reason_len | reason
```

Reason is ≤ 512 UTF-8 bytes and is diagnostic only; it MUST NOT contain
secrets. Unknown numeric codes are rejected or mapped to `PROTOCOL_ERROR` by
the receiver.

### 7.5 `WINDOW_UPDATE`

Exactly four bytes: `u32 credit` in `1..=8 MiB`. The sender consumes credit
before writing DATA; the receiver returns credit only after the consumer drains
those bytes. Initial windows are 256 KiB per stream and 8 MiB per connection.
Control frames (`RESET`, `PING`/`PONG`, `WINDOW_UPDATE`) are not credit-gated.

### 7.6 `PING` / `PONG`

`PING` MAY carry an opaque bounded challenge (≤ 64 KiB, but implementations
SHOULD keep it small). `PONG` MUST echo the most recent challenge it answers.
`PING`/`PONG` are end-to-end health checks and are distinct from WebSocket
protocol ping/pong.

### 7.7 `OPEN_WS`, `WS_MESSAGE`, `WS_CLOSE`

OpenCode PTY upgrades use ordinary WebSocket framing nested inside an OCT
stream. `OPEN_WS` opens the stream and carries the origin-form target, an
optional ordered subprotocol list, and non-hop-by-hop headers. The host connects
only to its fixed loopback origin, forwards the raw target/query (including a
single-use `ticket`), and never forwards the local gateway password.

`WS_MESSAGE` payload:

```text
u8 opcode | u8 flags | opaque application bytes
```

Opcode `0` is continuation, `1` text, `2` binary. Bit 0 of `flags` is FIN; all
other flag bits are reserved and rejected. A complete WebSocket message is split
into one or more `WS_MESSAGE` frames no larger than `MAX_FRAME_PAYLOAD`; the
first fragment carries Text/Binary, subsequent fragments carry Continuation, and
only the final fragment sets FIN. Receivers reassemble before delivery and cap a
complete message at 8 MiB. Message boundaries and the Text/Binary distinction
are preserved; binary PTY payloads are never decoded or rewritten. WebSocket
Ping/Pong remain local to each WebSocket hop and are not forwarded as
`WS_MESSAGE`.

`WS_CLOSE` payload:

```text
u16 code (0 = no code) | u16 reason_len | reason
```

The reason is UTF-8 and at most 123 bytes. Reserved/invalid close codes
(`1004`, `1005`, `1006`, `1015`, and values outside `1000..=4999`) are rejected.
`WS_CLOSE` replaces `END` for a WebSocket stream; after it both directions stop.
A malformed fragment, oversized reassembly, or unexpected HTTP frame on a WS
stream resets the stream with `PROTOCOL_ERROR`.

### 7.8 Noise transport envelope

E2EE mode first exchanges three Noise XX handshake messages as binary WSS
messages. Each begins with the ASCII magic `OCTN1`; the remainder is a Noise
message. After the handshake both endpoints install the Noise transport state.
Every subsequent binary WSS message is a Noise ciphertext of one complete OCT
inner frame. Relay control text messages are not encrypted by Noise and are
handled independently.

The Noise message limit is 65,535 bytes including the 16-byte tag. A one-byte
authenticated envelope distinguishes DATA from REKEY. Therefore an E2EE
endpoint uses a maximum inner-frame payload of 65,486 bytes
(`65,535 - 16 - 32 - 1`), rather than the plaintext 65,536-byte limit. WS messages
and DATA/WS_MESSAGE payloads are chunked to this limit. Receivers reject larger
frames and close the connection. The encrypted prelude described in §3 carries
the device name and optional one-time invite before the mux `HELLO`.

Every binary message after the handshake starts with an authenticated one-byte
envelope type: `DATA` or `REKEY`. A sender automatically emits `REKEY` after the
configured byte threshold (default 1 GiB); it sends the control message under
the old key, then rotates its outgoing cipher. The receiver rotates its incoming
cipher before processing subsequent messages. Rekey control messages are
authenticated by Noise and are never visible to the relay.

## 8. HTTP/SSE flow

1. The local gateway authenticates the incoming request, strips hop-by-hop and
   local-auth headers, and opens an HTTP stream with `OPEN_HTTP`.
2. The client sends the request body as `DATA` chunks followed by `END`.
3. The host reconstructs the request against the fixed upstream origin,
   preserving method, raw path+query, body bytes, and allowed duplicate
   headers.
4. The host sends `HTTP_RESPONSE` as soon as upstream status/headers arrive,
   then streams body bytes as `DATA`, then `END`.
5. The gateway forwards the real status/headers/body. It MUST NOT buffer an
   unbounded body. SSE is ordinary streaming `DATA`; each event is flushed.
6. If the local client cancels, the gateway sends `RESET(CANCELLED)` and the
   host cancels the upstream request.
7. If the carrier drops before a response, the gateway reports
   `HOST_OFFLINE`/`UNAVAILABLE`; it MUST NOT synthesize a success. SSE is
   live-only: reconnect re-fetches authoritative state and MUST NOT claim
   event replay.

## 9. Relay outer envelope

The relay endpoint is a WSS upgrade at `GET /oct/v1`. The first client message
is JSON text (`RelayControl`), max 16 KiB:

```json
{"type":"hello","protocol":1,"room":"0123456789abcdef","role":"host","token":"<64 hex chars>","client_version":"2.0.22"}
```

Relay replies:

```json
{"type":"ready","protocol":1,"room":"0123456789abcdef","role":"host"}
```

When the peer appears, both receive:

```json
{"type":"peer_joined","role":"client"}
```

Other control messages: `ping`, `pong`, `peer_left`, and
`error { code, message }`. After the handshake, every binary WebSocket message
is forwarded verbatim to the peer. The relay MUST NOT parse inner frames.

Room rules:

* room id: 16–128 ASCII alphanumerics, `-` or `_`;
* token: 32–256 printable ASCII; constant-time comparison;
* one host and one client per room; duplicate roles rejected;
* idle rooms expire; oversized binary messages are rejected;
* on peer disconnect the relay notifies and closes the other side; endpoints
  reconnect with a fresh epoch.

## 10. Error taxonomy

| Code | Name | HTTP mapping (gateway) |
|---:|---|---:|
| 1 | `UNAVAILABLE` | 503 |
| 2 | `UNAUTHORIZED` | 401 |
| 3 | `DENIED` | 403 |
| 4 | `OVER_LIMIT` | 413 |
| 5 | `BAD_REQUEST` | 400 |
| 6 | `CANCELLED` | 503 |
| 7 | `BACKEND_ERROR` | 503 |
| 8 | `PROTOCOL_ERROR` | 400 |
| 9 | `REQUEST_TIMEOUT` | 504 |
| 10 | `HOST_OFFLINE` | 503 |
| 11 | `HOST_REVOKED` | 503 |
| 12 | `VERSION_UNSUPPORTED` | 503 |
| 13 | `RECONCILIATION_REQUIRED` | 503 |

The gateway MUST distinguish its own 401 (local Basic auth) from an upstream
OpenCode 401 and MUST forward genuine upstream HTTP errors unchanged. Transport
failures (`RELAY_UNREACHABLE`, `HANDSHAKE_MISMATCH`, `BACKEND_UNHEALTHY`) are
endpoint-local conditions; they are not extra wire codes and are surfaced as
the closest taxonomy code plus a redacted local status.

## 11. Security invariants

* E2EE mode MUST wrap every inner frame in a Noise XX transport session with a
  pinned host static key; the relay sees ciphertext. The legacy mode is
  loopback-only and must never be exposed publicly.
* No plaintext fallback, no downgrade to an unknown protocol version.
* The host dials only its configured fixed loopback upstream. It never accepts
  arbitrary URLs, authority-form targets, or `CONNECT`.
* The local gateway MUST authenticate every HTTP route and WS upgrade, enforce
  Host/Origin policy, and bind only to loopback.
* No endpoint may log bodies, authorization headers, cookies, PTY tickets,
  room tokens, the local Basic password, or decrypted frames.
* Limits are security controls: bounded headers, frames, streams, queues, and
  pending bytes. Hostile input closes a stream or connection, not the process.
* Every reconnect uses a fresh epoch; stream ids and sequence counters MUST NOT
  continue across epochs with stale keys.

## 12. Implementation notes

The implementation intentionally diverges in these places; the implementation
is normative for this repository:

1. `END` trailers are not implemented. `END` is an empty half-close marker.
2. The numeric error taxonomy is frozen; transport-local conditions are not
   extra wire codes.
3. `PONG` may carry a challenge echo, so end-to-end PING/PONG works.
4. The feature enum is `http`, `sse`, `ws`, `e2ee`, `resync`; bit 0 is
   unused and unknown non-critical bits are ignored.
5. Nested PTY WS payload encoding is implemented as specified in §7.7 with a
   complete-message cap of 8 MiB.
6. Plaintext inner payloads are capped at exactly 64 KiB. E2EE mode uses a
   65,487-byte payload cap so the encoded frame plus the Noise tag fits the
   65,535-byte Noise message limit.
7. `decode_frame_exact` is part of the public API and is re-exported from the
   crate root.

## 13. Conformance checklist

- [ ] Reject a frame with version ≠ 1.
- [ ] Reject `payload_len` > 65,536 before allocating.
- [ ] Round-trip every defined kind and empty/non-empty payload boundary.
- [ ] Reject `END` with a payload and unknown critical flags.
- [ ] Reject zero, wrong-parity, duplicate, and reused stream ids.
- [ ] Reject data after `END`/`RESET` and out-of-order sequence numbers.
- [ ] Reject absolute-form targets, `CONNECT`, and header injection.
- [ ] Enforce header count/byte limits and method/target limits.
- [ ] Negotiate HELLO limits as an intersection; reject major mismatch.
- [ ] Relay pairs one host and one client, rejects duplicate roles/tokens, and
      forwards binary payloads without parsing them.
- [ ] Carrier loss resets all open streams with `UNAVAILABLE`.
- [x] E2EE: every inner frame is ciphertext; wrong-pin/plaintext fails.
