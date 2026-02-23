# threat.gg Agent

The honeypot agent for [threat.gg](https://threat.gg), a honeypot-as-a-service platform for collecting and analyzing real-world attack data.

## Overview

The agent is a Go binary that runs on honeypot nodes and emulates multiple network services. When attackers connect and interact with these fake services, the agent captures their activity (commands, credentials, payloads) and reports it to the threat.gg server via gRPC.

## Supported Honeypots

| Service | Default Port | Description |
|---------|-------------|-------------|
| SSH | 22 | Captures brute-force credentials, shell commands, proxy requests, and malware drops |
| PostgreSQL | 5432 | Emulates a PostgreSQL server, captures authentication attempts and SQL queries |
| FTP | 21 | Captures FTP login attempts and file transfer commands |
| Elasticsearch | 9200 | Emulates an Elasticsearch REST API, captures search and index requests |
| HTTP | 8080 | Web server honeypot capturing HTTP request payloads |
| Kubernetes API | 6443 | Emulates the Kubernetes API server |
| OpenClaw | 18789 | WebSocket-based honeypot for custom protocol interactions |
| Kafka | 9092 | Emulates an Apache Kafka broker, captures client reconnaissance and SASL/PLAIN credentials |

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
