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
- Adjust replicas/HPA after measuring room churn; each room is an in-memory
  host+client pair, so relay affinity is not required for correctness.
