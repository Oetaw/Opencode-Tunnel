# Deployment

## Docker Compose (Caddy TLS)

```sh
cd deploy/relay
cp .env.example .env
# OCT_DOMAIN=relay.example.com
# OCT_ACME_EMAIL=ops@example.com
docker compose -f compose.public.yaml up -d --build
```

Caddy publishes 80/443 and obtains a certificate. The relay binds a private
container interface with `--allow-public`; do not publish its port. Health:
`https://<domain>/healthz`.

The relay container is non-root, read-only, capability-dropped and resource
limited. Edge per-IP rate limiting and monitoring belong at the ingress or
firewall layer. The relay defaults to 512 rooms and a 32 MiB aggregate
peer-queue budget; tune `--max-rooms` and `--max-queued-bytes` to the container
memory limit rather than removing them.

## Kubernetes

See [`deploy/kubernetes`](../deploy/kubernetes). Apply with Kustomize:

```sh
kubectl apply -k deploy/kubernetes
```

The manifests include a non-root deployment, probes, resource limits, PDB,
NetworkPolicy and an Ingress example. The relay keeps rooms in memory, so the
base runs one active replica with `Recreate`; do not raise replicas until a
distributed room-affinity layer exists. Set the image, host and TLS secret
for your cluster. `/healthz` is public through the Ingress; `/metrics` is
intended for in-cluster Prometheus only. The Docker/Caddy reference proxies only
`/oct/v1` and `/healthz`, never `/metrics`.

## systemd host

Use `deploy/host/oct-host.service` as a starting point:

- `EnvironmentFile` (0600) for `OCT_ROOM`, `OCT_TOKEN`, `OPENCODE_PASSWORD`.
- `--state-dir` on persistent disk, mode 0700.
- `--e2ee` is the default; do not add `--no-e2ee`.
- Keep `opencode serve` on 127.0.0.1.
- `loginctl enable-linger` if the user service must survive logout.

## Upgrades

1. Build or pull the new `oct` binary/image.
2. Run `cargo test --workspace` (or CI) on the candidate.
3. Upgrade the relay first, then host, then client.
4. Keep the previous binary/image for rollback.
5. Never delete the host identity unless you intend to rotate identity and
   re-pair every client.

## Resource guidance

- Relay: 1 vCPU / 256 MiB is enough for small teams; scale with connection
  count and room churn.
- Host/client: mostly idle; PTY and SSE traffic are bounded by flow control.
- Use persistent disk for host/client state, not the relay.
