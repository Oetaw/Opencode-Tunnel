# Deployment

## Docker Compose (Caddy TLS)

```sh
cd deploy/relay
cp .env.example .env
# OCT_DOMAIN=relay.example.com
# OCT_ACME_EMAIL=ops@example.com
# OCT_RELAY_ADMISSION_TOKEN=$(openssl rand -hex 32)
docker compose -f compose.public.yaml up -d --build
```

Caddy publishes 80/443 and obtains a certificate. The relay binds a private
container interface with `--allow-public`; do not publish its port. Health:
`https://<domain>/healthz`.

If nginx is the edge, use [`deploy/relay/nginx.conf.example`](../deploy/relay/nginx.conf.example)
as a starting point. It proxies only exact `/oct/v1` and `/healthz`, adds HSTS,
and applies per-IP upgrade rate and concurrent-connection limits. The live edge
must be checked separately; the example is not automatically applied.

`OCT_RELAY_ADMISSION_TOKEN` is a required secret. Configure the same value as
`OCT_TOKEN` on the host. Room creation and the host role require it, so a
client token can never create rooms or squat the host slot. Never put it in the
host's invite; `oct invite` derives a separate client token.

The relay container is non-root, read-only, capability-dropped and resource
limited. Edge per-IP rate limiting and monitoring belong at the ingress or
firewall layer. The relay defaults to 512 rooms and a 32 MiB aggregate
peer-queue budget; tune `--max-rooms` and `--max-queued-bytes` to the container
memory limit rather than removing them. Keep per-IP connection limits and
alerting at the edge.

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

Create the host-admission secret before rollout; the deployment reads it as
`OCT_RELAY_ADMISSION_TOKEN`:

```sh
kubectl -n oct create secret generic oct-relay-admission \
  --from-literal=token="$(openssl rand -hex 32)"
```

Set the same value as `OCT_TOKEN` on the host. Rotating it requires restarting
the relay and all hosts, and re-pairing clients if the room changes.

## systemd host

Use `deploy/host/oct-host.service` as a starting point:

- `EnvironmentFile` (0600) for `OCT_ROOM`, `OCT_TOKEN`, `OPENCODE_PASSWORD`.
- `--state-dir` on persistent disk, mode 0700.
- `--e2ee` is the default; do not add `--no-e2ee`.
- Keep `opencode serve` on 127.0.0.1.
- `loginctl enable-linger` if the user service must survive logout.

## Upgrades

1. Build or pull the new `oct` binary/image.
2. Run the release gates on the candidate.
3. Set `OCT_RELAY_ADMISSION_TOKEN` on the relay and the same value as
   `OCT_TOKEN` on the host; restart the relay first, then the host. Relay
   control protocol 2 is not compatible with old protocol-1 clients.
4. Re-pair clients or update their stored client token as part of the cutover.
5. Keep the previous binary/image and old environment file for rollback.
6. Never delete the host identity unless you intend to rotate identity and
   re-pair every client.

For a mixed-version outage, roll back both relay and host together. A new host
cannot create a role-separated room on an old relay, and an old host cannot
create a room on a relay that requires admission.

## Resource guidance

- Relay: 1 vCPU / 256 MiB is enough for small teams; scale with connection
  count and room churn.
- Host/client: mostly idle; PTY and SSE traffic are bounded by flow control.
- Use persistent disk for host/client state, not the relay.
