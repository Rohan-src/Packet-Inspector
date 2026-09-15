# Packet Analyzer Monitoring

This folder adds Prometheus + Grafana monitoring without modifying the original Java source files under `src/main/java/packet_analyzer/`.

## 1. Build the original application
From the project root:

```bash
mvn package
```

## 2. Build the monitoring module

```bash
cd monitoring
mvn package
```

## 3. Run MonitoringMain

The monitoring launcher needs the original application's compiled classes plus the monitoring dependencies on its classpath. The easiest IDE setup is to add `monitoring/src/main/java` as a source root and add the monitoring Maven dependencies to the run configuration classpath.

Arguments are the same as the original application:

```text
<input.pcap> <output.pcap> [--block-ip ...] [--block-app ...] [--block-domain ...] [--lbs n] [--fps n]
```

The launcher starts the original `packet_analyzer.Main` unchanged, reads its existing console report, and publishes those values at:

`http://localhost:9400/metrics`

## 4. Start Prometheus + Grafana

From this folder:

```bash
docker compose up -d
```

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

Grafana is provisioned with a Prometheus datasource and a Packet Analyzer dashboard automatically.

### Windows / Docker Desktop
`host.docker.internal` is used so the containers can scrape the Java monitoring server running on the host machine.

## Important design choice

The original packet analyzer Java files are intentionally untouched. The monitoring launcher observes the application's existing report instead of adding Prometheus calls inside the packet-processing logic.
