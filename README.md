# threat.gg Agent

The honeypot agent for [threat.gg](https://threat.gg), a honeypot-as-a-service platform for collecting and analyzing real-world attack data.

## Overview

The agent is a Go binary that runs on honeypot nodes and emulates multiple network services. When attackers connect and interact with these fake services, the agent captures their activity (commands, credentials, payloads) and reports it to the threat.gg server via gRPC.

## Supported Honeypots

| Service | Default Port | Description |
|---------|-------------|-------------|
| SSH | 22 | Captures brute-force credentials, shell commands, proxy requests, and malware drops |
| PostgreSQL | 5432 | Emulates a PostgreSQL server, captures authentication attempts and SQL queries |
| Microsoft SQL Server | 1433 | Emulates TDS 7.x, captures LOGIN7 credentials/client metadata and SQL batches |
| FTP | 21 | Captures FTP login attempts and file transfer commands |
| Elasticsearch | 9200 | Emulates an Elasticsearch REST API, captures search and index requests |
| HTTP | 8080 | Web server honeypot capturing HTTP request payloads |
| Kubernetes API | 6443 | Emulates the Kubernetes API server |
| Kubelet | 10250 | Emulates the node HTTPS API, including pods, metrics, logs, stats, and exec/run capture |
| Consul | 8500 | Emulates service discovery, health, KV, session, and ACL-token HTTP APIs |
| OpenClaw | 18789 | WebSocket-based honeypot for custom protocol interactions |
| Kafka | 9092 | Emulates an Apache Kafka broker, captures client reconnaissance and SASL/PLAIN credentials |
| VNC | 5900 | Emulates VNC/RFB handshake and captures auth challenge-response + client preferences |

## Architecture

Each honeypot implements the `honeypots.Honeypot` interface (`Start()` + `Name()`) and is registered in `main.go`. Honeypots run concurrently as goroutines, listening on their respective ports.

Captured attack data is sent asynchronously to the threat.gg server via gRPC with TLS and API key authentication. The server stores the data in PostgreSQL and broadcasts events to the real-time dashboard feed via Redis pub/sub.

## Building

```bash
make build        # Cross-compile static Linux binaries (amd64 + arm64)
make proto        # Regenerate protobuf code from the server's honeypot.proto
make test         # Run tests
```

## Deployment

The agent binary is deployed to honeypot nodes at `/root/honeypot` and managed via systemd. An auto-updater checks GitHub Releases every 15 minutes for new versions (calver tags).

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `API_KEY` | API key for server authentication | required |
| `GO_ENV` | Set to `development` for local testing | `production` |
| `SSH_PORT` | SSH honeypot port | `22` |
| `KAFKA_PORT` | Kafka honeypot port | `9092` |
| `MSSQL_HONEYPOT_PORT` | Microsoft SQL Server honeypot port | `1433` |
| `KUBELET_HONEYPOT_PORT` | Kubelet HTTPS honeypot port | `10250` |
| `CONSUL_HONEYPOT_PORT` | Consul HTTP API honeypot port | `8500` |

The MSSQL honeypot intentionally advertises `ENCRYPT_NOT_SUP` so it can observe
LOGIN7 reconnaissance and reversibly obfuscated SQL-auth attempts. Run honeypot
nodes on an isolated capture network; do not place legitimate credentials or
production database traffic on the listener's network path.
