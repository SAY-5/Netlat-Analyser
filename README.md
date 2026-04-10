# netlat

A tool that reads network traffic recordings and tells you what went wrong.

## The problem

When two computers talk to each other over a network, sometimes things go wrong. Messages arrive late, get lost, or the connection breaks entirely. Figuring out *why* from a raw packet capture is painful. You end up scrolling through thousands of lines in Wireshark trying to spot the one flow that's misbehaving and then manually piecing together what happened.

I kept doing this over and over during production incidents, so I wrote this tool to do it for me.

## What it does

You give netlat a `.pcap` file (a recording of network traffic, usually from tcpdump), and it gives you back a report saying things like:

- "This connection between server A and server B has a round-trip time of 2ms normally, but it spiked to 340ms at 14:23:07"
- "12 packets had to be sent twice because the first copy got lost"
- "The receiver ran out of buffer space and told the sender to stop for 800ms"

It groups all the packets into conversations ("flows"), tracks what's happening in each one, measures how fast replies come back, notices when packets go missing, and flags anything unusual.

### How round-trip time gets measured

Round-trip time (RTT) is how long it takes for a message to go out and the reply to come back. Like if you shout into a canyon and time the echo.

netlat measures this three different ways because no single method works perfectly:

**Method 1 - Connection setup timing.** When two computers first connect over TCP, they do a three-step handshake (SYN, SYN-ACK, ACK). Timing that gives you one clean RTT sample right at the start.

**Method 2 - TCP timestamp matching.** Most modern systems embed a little clock value in each packet (TSval/TSecr, defined in RFC 7323). When the other side echoes it back, you can compute the round trip. This gives you continuous measurements throughout the connection.

**Method 3 - Sequence number tracking.** Every TCP data segment has a sequence number, and the receiver acknowledges it. Match the data to its ACK and you've got an RTT. Noisier than the other two, but works even when timestamps aren't available.

One important detail: if a packet got retransmitted, we throw away that RTT measurement. We can't tell if the ACK is responding to the original send or the retransmit, so the number would be meaningless. This is called Karn's algorithm and getting it wrong is the most common reason other tools report garbage RTT values.

### How retransmissions get classified

When the same data gets sent twice (same sequence number range appears again), that's a retransmission. But the *reason* matters:

- **fast retransmit** - The receiver noticed a gap and sent duplicate ACKs. After 3 of those, the sender resends the missing piece without waiting. Usually means one packet got dropped somewhere.
- **timeout (RTO)** - The sender waited and waited, nothing came back, the retransmit timer fired. This is worse. The path might be completely dead.
- **tail loss** - The last few packets in a burst vanished. These are sneaky because there's nothing coming after them to trigger duplicate ACKs, so the sender has to wait for a timeout.
- **spurious** - The packet wasn't actually lost. It just arrived out of order, the sender retransmitted anyway, and later a D-SACK block confirmed the original made it through fine.
- **unknown** - Doesn't fit any of the above patterns. Not enough context to tell.

### How anomalies get detected

For each flow, netlat tracks a running average of RTT (using something called EWMA - exponentially weighted moving average). It also tracks how much the RTT normally varies. When a new sample comes in that's way outside the normal range (more than 3 standard deviations by default), it flags it as a spike.

It waits until it has at least 10 samples before it starts flagging anything, so you don't get false alarms on short-lived connections.

Besides RTT spikes, it also watches for:
- **Burst loss** - 5 or more retransmissions crammed into a 100ms window. That's not random packet loss, something happened.
- **Zero window** - The receiver told the sender "stop sending, my buffer is full" and kept saying that for over 500ms. The application is probably not reading fast enough.
- **Resets** - The connection got terminated with a RST. Could be normal, could be a firewall killing things.
- **Slow handshake** - The initial TCP handshake took over a second. Probably a network or server issue.

All the thresholds are configurable if the defaults don't work for your environment.

## Architecture

Here's how data flows through netlat, from a raw pcap file to a useful report:

```
                          You have a .pcap file
                          (recorded network traffic)
                                   |
                                   v
                     +-------------------------+
                     |      Packet Parser      |
                     |    (pcap/dpkt_backend)   |
                     +-------------------------+
                       Reads the raw file using
                       a library called dpkt.
                       Handles different formats
                       (Ethernet, VLAN tags, IPv4,
                       IPv6). Pulls out the fields
                       we care about: IPs, ports,
                       sequence numbers, flags,
                       TCP timestamps, etc.
                                   |
                          stream of Packet objects
                                   |
                                   v
                     +-------------------------+
                     |      Flow Tracker       |
                     |    (flows/tracker)       |
                     +-------------------------+
                       Groups packets into TCP
                       connections. Tracks the
                       state of each connection
                       (is it still setting up?
                       transferring data? closing?).
                       Keeps per-direction counters:
                       which sequence numbers have
                       been sent, which have been
                       acknowledged, etc.
                                   |
                      for each packet, we now know
                      which flow it belongs to and
                      the full state of that flow
                                   |
                   +---------------+---------------+
                   |               |               |
                   v               v               v
          +--------------+ +--------------+ +--------------+
          | RTT Estimator| |  Retransmit  | |   Anomaly    |
          | (analysis/   | |  Detector    | |   Detector   |
          |  rtt)        | | (analysis/   | | (analysis/   |
          |              | |  retransmit) | |  anomaly)    |
          +--------------+ +--------------+ +--------------+
           Measures how     Spots when the   Keeps a running
           fast replies     same data gets   average of RTT
           come back.       sent twice.      per flow. Flags
           Three methods    Figures out if   anything that
           (handshake,      it was caused    looks abnormal:
           timestamps,      by dup ACKs,     spikes, burst
           seq/ack).        a timeout,       loss, zero
           Filters out      tail loss, or    windows, resets.
           retransmitted    reordering.
           packets.
                   |               |               |
                   +-------+-------+-------+-------+
                           |               |
                           v               v
                  +--------------+  +--------------+
                  |    Report    |  |  Prometheus  |
                  |   Renderer   |  |   Exporter   |
                  |  (report/    |  |  (export/    |
                  |   render)    |  |  prometheus) |
                  +--------------+  +--------------+
                   Formats the       Exposes the
                   results as        numbers as
                   human-readable    metrics that
                   text or JSON.     Prometheus can
                   Prints to the     scrape. Pairs
                   terminal or       with a Grafana
                   writes to a       dashboard for
                   file.             live graphs.
```

The whole thing is orchestrated by `analysis/pipeline.py`, which wires these pieces together and streams packets through in a single pass. It never loads the entire file into memory, so you can point it at a multi-gigabyte capture without worrying about RAM.

Each component is independent. The RTT estimator doesn't know about anomaly detection. The retransmit detector doesn't know about reports. The pipeline just passes the right data to each one in order. This makes it straightforward to test each piece on its own (which is why there are ~125 tests).

The flow tracker has a size limit (100k flows by default). If you're analyzing a capture with more concurrent connections than that, it evicts the oldest idle flows to stay within the budget. In practice, even on busy servers, most captures don't come close to that limit.

## Install

```
git clone https://github.com/SAY-5/Netlat-Analyser.git
cd Netlat-Analyser
pip install -e ".[dev]"
```

You need Python 3.10 or newer. The only real dependency for packet parsing is a library called dpkt. No compiled C code, nothing that's hard to install.

## Usage

Analyze a pcap file:

```bash
netlat analyze --pcap capture.pcap
```

That prints a human-readable report to the terminal. If you want JSON instead (for feeding into other tools):

```bash
netlat analyze --pcap capture.pcap --format json -o report.json
```

If you only care about traffic to one specific service:

```bash
netlat analyze --pcap capture.pcap --focus 10.0.1.5:443
```

Or a whole subnet:

```bash
netlat analyze --pcap capture.pcap --focus 10.0.0.0/24
```

If you have a long capture but only care about the last 30 seconds:

```bash
netlat analyze --pcap capture.pcap --time-window 30s
```

### Capturing traffic

netlat can also record traffic for you (wraps tcpdump, needs root):

```bash
sudo netlat capture --iface eth0 --filter tcp --duration 60 -o /tmp/cap.pcap
```

### Prometheus metrics

If you want to pipe the analysis into a monitoring system:

```bash
netlat serve --pcap capture.pcap --port 9090
```

Then point Prometheus at `localhost:9090/metrics`. There's a ready-to-import Grafana dashboard in `dashboards/grafana_dashboard.json`.

## Running it in Kubernetes

There's a DaemonSet manifest in `deploy/k8s/` that puts a capture agent on every node in your cluster. It records TCP headers, rotates the pcap files so they don't eat the disk, and exposes metrics for Prometheus to scrape.

```bash
docker build -t netlat:latest -f deploy/Dockerfile .
kubectl apply -f deploy/k8s/daemonset.yaml
./scripts/k8s_collect.sh    # copies pcaps off all the pods
```

The DaemonSet needs `hostNetwork` (to see actual traffic, not just container-to-container) and `CAP_NET_RAW` (to run tcpdump). There's a full step-by-step runbook at `deploy/RUNBOOK.md`.

## CLI reference

`netlat analyze`:

- `--pcap` - path to the pcap file (required)
- `--format` - `text` or `json`, defaults to text
- `--output` - write to a file instead of printing to terminal
- `--focus` - only look at traffic matching this filter. Accepts an IP address, a CIDR range like `10.0.0.0/24`, a port like `:443`, or a combo like `10.0.1.5:443`
- `--time-window` - only analyze the last N of the capture. Examples: `10s`, `1m`, `5m`
- `--anomaly-rtt-multiplier` - how many standard deviations before flagging an RTT spike, default 3.0
- `--anomaly-retrans-pct` - retransmit rate threshold in percent, default 5.0

Environment variables: `NETLAT_LOG_LEVEL` (default INFO), `NETLAT_LOG_FORMAT` (set to `json` for structured logs).

## Project structure

```
src/netlat/
  cli.py                 command line interface (built with typer)
  pcap/dpkt_backend.py   reads pcap files, parses packet headers
  flows/models.py        data structures for packets, flows, events
  flows/tracker.py       reconstructs TCP connections from raw packets
  analysis/rtt.py        measures round-trip time
  analysis/retransmit.py finds and classifies retransmissions
  analysis/anomaly.py    detects unusual patterns
  analysis/pipeline.py   connects all the above together
  report/render.py       formats output as text or JSON
  export/prometheus.py   exposes metrics for monitoring
  capture/tcpdump.py     manages tcpdump for live capture
  util/bpf.py            helper for building packet filters

tests/                   ~125 tests covering everything above
deploy/                  Dockerfile, Kubernetes manifests, ops runbook
dashboards/              Grafana dashboard JSON
scripts/                 demo script, pcap generators, k8s collection
```

## Development

```bash
pip install -e ".[dev]"
make test          # runs the full test suite
make lint          # code style checks
make typecheck     # type checking with mypy
make demo          # generates a fake incident and analyzes it
```

## Try it out

If you don't have a pcap file handy, run the demo:

```bash
python3 scripts/demo.py
```

It generates a fake capture with three TCP connections: one that's perfectly healthy, one that develops a latency spike partway through, and one that's losing packets. Then it runs the full analysis and shows you what it found. Good way to get a feel for what the output looks like.

## License

MIT
