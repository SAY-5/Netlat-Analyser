# netlat k8s runbook

How to run netlat as a DaemonSet for cluster-wide packet captures.

## What you need

- k8s 1.24+, kubectl configured
- Docker (to build the image)
- Cluster admin - the DaemonSet needs hostNetwork and NET_RAW
- Prometheus + Grafana if you want dashboards (optional)

## Setup

Build the image:

```
docker build -t netlat:latest -f deploy/Dockerfile .
```

If you're not using kind/minikube, push it somewhere your cluster can pull from:

```
docker tag netlat:latest your-registry.io/netlat:latest
docker push your-registry.io/netlat:latest
```

Then edit `deploy/k8s/daemonset.yaml` and fix the image reference.

Deploy:

```
kubectl apply -f deploy/k8s/daemonset.yaml
```

Check it's running:

```
kubectl get pods -n netlat -o wide
kubectl logs -n netlat -l app.kubernetes.io/name=netlat --tail=20
```

## Capturing

The DaemonSet default is a 1-hour TCP capture on eth0, headers only (96 byte snaplen), with 100MB file rotation.

To change the capture parameters, edit the `args` in the daemonset spec:

```yaml
args:
  - "capture"
  - "--interface=eth0"
  - "--duration=300"              # 5 minutes
  - "--bpf-filter=tcp port 443"  # just HTTPS
  - "--output-dir=/captures"
```

To filter to a specific service:

```
SVC_IP=$(kubectl get svc my-service -o jsonpath='{.spec.clusterIP}')
# then set --bpf-filter="host ${SVC_IP}"
```

## Collecting pcaps

The collect script copies captures off every pod and optionally runs analysis:

```
./scripts/k8s_collect.sh ./my_captures
./scripts/k8s_collect.sh ./my_captures --analyze
```

Or manually:

```
kubectl cp netlat/<pod>:/captures/ ./local_dir/
```

## Prometheus

If you already have Prometheus with pod scraping, it should pick up netlat automatically - the pods have the standard annotations (`prometheus.io/scrape: "true"`, port 9090).

If not, you can apply `deploy/prometheus.yml` as a scrape config.

Verify it's working:

```
kubectl port-forward -n netlat <pod> 9090:9090
curl localhost:9090/metrics | head
```

Import `dashboards/grafana_dashboard.json` into Grafana for the pre-built panels.

## Stuff that causes latency in k8s

Things I've seen in the wild, roughly in order of how annoying they are to debug:

**DNS** - first-connection latency often turns out to be slow DNS. Check CoreDNS pod count, look for search domain expansion bloat.

**CNI overhead** - overlay networks add latency. Compare same-node pod-to-pod vs cross-node. If you're on an overlay CNI and latency matters, look at Cilium with eBPF or host-routing mode.

**iptables rules** - kube-proxy in iptables mode gets slow as service count grows. Thousands of services = measurable per-packet overhead. Switch to IPVS mode.

**Cross-AZ traffic** - obvious in theory, easy to miss in practice. Check if your slow flows happen to cross availability zones. Pod affinity or topology-aware routing helps.

**CPU throttling** - CFS throttling causes periodic latency spikes that look random until you check cgroup stats. Look at `nr_throttled` in `/sys/fs/cgroup/cpu/`. Often the fix is raising CPU limits or switching to burstable QoS.

**Network policies** - some CNIs implement NetworkPolicy by inserting more iptables rules. Adding policies can add measurable latency.

**Service mesh sidecars** - Istio/Linkerd add ~1-5ms per hop. If you see that consistently, it's expected. If it's higher, check sidecar resource limits.

## Troubleshooting

Pods won't start:
```
kubectl describe ds netlat -n netlat
kubectl get events -n netlat --sort-by=.lastTimestamp
```
Usually one of: image pull failure, PodSecurityPolicy blocking hostNetwork/NET_RAW, or node resources.

No captures being written:
```
kubectl exec -n netlat <pod> -- tcpdump -D
kubectl exec -n netlat <pod> -- df -h /captures
```
Check that the interface name is right and there's disk space.

## Teardown

```
kubectl delete -f deploy/k8s/daemonset.yaml
```

Captures stay on the nodes at `/var/lib/netlat/captures` - clean those up manually if you care.
