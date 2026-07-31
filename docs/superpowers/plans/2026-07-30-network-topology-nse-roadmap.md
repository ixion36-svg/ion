# Network Topology (NSE view) — Roadmap

**Status:** Forks decided (2026-07-30) — build queued after the Attack Path roadmap + v0.63.1 security release. A=Arkime+ES (SNMP deferred) · B=subnet /24 + host drill-down · C=label gaps as unavailable · D=vis-network (all recommended).
**Date:** 2026-07-30
**Type:** Feature on shared rails (Arkime/ES) — lands in the Topology/Network nav
**Owning principle:** *Show the NSE real flow metrics from data we already ingest; label what we can't source, don't fake it.*

Prompted by Elastic's new Kibana **Network Topology** plugin. That feature is **SNMP device topology** — nodes = SNMP devices, edges = L2/L3 adjacency (ARP/MAC/BGP/OSPF), metrics = interface counters + routing state. It answers *"what is physically connected to what"* and is thin on bandwidth/throughput/latency. ION's **Arkime** data is the complement: rich packet-flow volumetrics (talkers, bytes, protocols, geo, throughput) but **no flow-topology graph today**. This feature fills that gap — a flow-based topology an NSE actually reads.

## 1. Current state (what ION has)
- Arkime traffic analytics (`arkime_service.py`, `/api/arkime/traffic/*`, `arkime_traffic.html`): top-talkers, protocol mix, throughput timeline (`src/dst_histo`), geo, per-node volume.
- `/topology` today = **SOC service-health** graph (ES/Kibana/etc.), NOT network flow. `/network-map` = CMDB asset table. So a host/subnet **flow-topology graph is a genuine gap**.
- Renderer already bundled + CSP-safe: **vis-network** (`static/js/vis-network.min.js`, used in `knowledge_graph.html`).

## 2. NSE-metric availability (build only what's real; label the rest)
| Metric | Status | Source |
|---|---|---|
| Top talkers (bytes) | **HAVE** | `arkime_service.get_top_talkers` |
| Protocol distribution | **HAVE** | `get_traffic_overview` |
| Bytes/packets, throughput timeline | **HAVE** | `totBytes`/`packets`, `src/dst_histo` |
| Geo distribution | **HAVE** | `get_top_countries` |
| Per-node (sensor) volume | **HAVE** (link proxy) | `get_per_node_traffic` |
| Conversation pairs (edges) | **DERIVE-NOW** | pair-key the existing talker session sample |
| Port distribution, active-conversation count | **DERIVE-NOW** | aggregate `srcPort/dstPort`, distinct `communityId` |
| Throughput-per-edge (bytes/sec) | **DERIVE-NOW** | bytes ÷ (`lastPacket−firstPacket`) |
| Retransmit / TCP-error rate | **GAP** | Arkime has no native retransmit counter → needs added tcp-flag fields or Packetbeat |
| RTT / latency, packet loss | **GAP** | needs Packetbeat |
| Per-interface utilization + interface health | **GAP** | needs **SNMP IF-MIB** (exactly what Elastic built) |

## 3. The topology graph (centerpiece)
- **Nodes** = hosts, collapsible to **subnet /24** or CMDB asset (`NetworkAsset` join). Size ∝ bytes; badge = threat (join `network_correlation_report_service` IOC/actor rollups + OpenCTI verdict).
- **Edges** = conversations (src↔dst), weight ∝ bandwidth, label = dominant protocol/port, **colour = health** (error/retransmit when sourceable, else beaconing/threat).
- Build: new `arkime_service.get_conversations()` (pair-keyed aggregation of the existing session sample) → topology API → `{nodes, edges}` JSON → **vis-network** render.

## 4. Phased roadmap
- **Phase 0 — Metrics service (compute-on-read).** `get_conversations()` + port/active-conversation aggregation in `arkime_service`; new `topology_metrics_service.py` joining Arkime volumetrics + ES `community_id`/`arkime_node` linkage + threat rollups + asset labels. New read endpoint `/api/arkime/traffic/topology` (`alert:read`, reuse exclusion plumbing). No new ingestion — air-gap-safe, on-prem Arkime.
- **Phase 1 — Topology graph UI.** New tab in the Topology/Network nav; render `{nodes, edges}` with bundled vis-network; node/edge tooltips = the NSE metrics panel; **gap metrics shown as "not available — requires Packetbeat/SNMP"** (NSE credibility). Advisory.
- **Phase 2 — Health/anomaly overlays.** Edge colour by beaconing/error-rate/threat; time-scrub over throughput; "pull PCAP" deep-link from an edge (`community_id` → existing Arkime download). Optional later: opt-in SNMP IF-MIB collection to close interface-health/RTT gaps (Elastic's approach).

## 5. Open forks (decide before Phase 0)
- **A — Data source (v1):** Arkime-only vs **Arkime+ES** (adds alert/threat context via `community_id`) vs +Packetbeat/SNMP (only way to close RTT/retransmit/interface gaps). Rec: **Arkime+ES for v1, SNMP deferred**.
- **B — Graph grouping:** host-level vs **subnet /24 default + host drill-down** (rec — scales, NSE-readable) vs CMDB-asset.
- **C — v1 metric scope:** ship real-now + derive-now (talkers, protocol/port, throughput, conversations, per-node util); **explicitly label RTT/retransmit/packet-loss/interface-health as unavailable** rather than fake them (rec).
- **D — Renderer:** **vis-network** (rec — bundled, force-directed, fits a dense flow graph) vs reuse the attack-path SVG-DAG.
