# Kubernetes deployment

Example production topology for the relay only. Host and client run outside
the cluster, next to OpenCode and the local TUI.

1. Build/publish the image, or use the release image.
2. Replace `relay.example.com` in `deployment.yaml` and `ingress.yaml`.
3. Create the TLS secret `oct-relay-tls` (cert-manager, sealed-secrets or your
   ingress controller's certificate mechanism).
4. Apply with Kustomize:

```sh
kubectl apply -k deploy/kubernetes
kubectl -n oct rollout status deploy/oct-relay
```

Notes:

- Only `/oct/v1` and `/healthz` are exposed through the Ingress.
- `/metrics` is scraped in-cluster by the optional ServiceMonitor.
- `--allow-public` is required because the relay binds `0.0.0.0` inside the
  cluster, but the container port is never exposed outside the cluster except
  through the Ingress.
- Endpoint E2EE remains mandatory. The relay still sees only ciphertext.
- The relay keeps rooms in memory. This base intentionally runs one active
  replica; do not raise `replicas` or enable `hpa.yaml` until a distributed
  room/affinity layer exists, or hosts and clients may land on different pods.
- `pdb.yaml` protects the active pod during voluntary disruptions. A rolling
  update uses `Recreate` to avoid two room tables serving one relay URL.
- For multi-region/HA, run independent relay deployments with distinct DNS
  names/rooms, or implement distributed room routing first.
