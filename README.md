# Packet Inspector — Multi-Threaded Network Packet Analyzer

Packet Inspector is a Java-based network packet analysis system that reads packets from PCAP files, parses network protocols, identifies application-level information, and processes packets through a multi-threaded forwarding pipeline.

The project demonstrates practical concepts in **Computer Networking, Java Multithreading, Packet Parsing, Concurrent Processing, and System Observability**.

## 🚀 Features

- Reads and processes packets from PCAP files
- Parses network packet headers and protocol information
- Supports TCP and UDP traffic analysis
- Identifies application-level protocols and domains/SNI where available
- Uses multiple worker threads for concurrent packet processing
- Implements load-balancer based packet distribution
- Uses fast-path workers for packet processing
- Tracks forwarded and dropped packets
- Generates an output PCAP file
- Provides processing statistics after execution
- Includes optional Prometheus and Grafana monitoring
- Runs Prometheus and Grafana using Docker Compose

---

## 🏗️ Architecture

```text
                    PCAP File
                       │
                       ▼
                ┌──────────────┐
                │ Packet Reader│
                └──────┬───────┘
                       │
                       ▼
                ┌──────────────┐
                │ Packet Parser│
                └──────┬───────┘
                       │
                       ▼
             ┌────────────────────┐
             │ Load Balancers     │
             │ LB0 / LB1          │
             └─────────┬──────────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       ┌────────────┐      ┌────────────┐
       │ Fast Path  │      │ Fast Path  │
       │ Workers    │ ...  │ Workers    │
       └──────┬─────┘      └──────┬─────┘
              │                   │
              └─────────┬─────────┘
                        ▼
                 Packet Processing
                        │
                        ▼
                  Output PCAP
