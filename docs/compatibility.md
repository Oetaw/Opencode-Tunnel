# Compatibility

OCT speaks the OpenCode V2 HTTP/SSE/WebSocket API through a local gateway. It
does not modify or fork OpenCode.

## Tested combinations

| OCT | OpenCode | OS | Status |
|---|---|---|---|
| 0.1.x | 2.0.22 | macOS arm64, Ubuntu 24.04 | parity + PTY + TUI tested |
| 0.1.x | 2.0.28 | Ubuntu 24.04 | API/PTY/TUI smoke tested |

The TUI version should match the server version. Mixing client and server
versions can hang during startup; upgrade both together.

## OpenCode state

OCT stores no OpenCode database or provider credentials. The remote OpenCode
service remains authoritative for sessions, messages, files, providers and
permissions. Do not copy `opencode.db`, `auth.json` or credential values between
machines.

## Network

- Relay: WSS on 443 through a TLS terminator.
- Host/client: outbound WSS only; no inbound public ports.
- Local gateway/OpenCode: loopback only.
