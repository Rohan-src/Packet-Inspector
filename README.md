# 📦 Packet Inspector

> A multi-threaded Java-based network packet analyzer for processing and analyzing PCAP files.

## 📖 Overview

**Packet Inspector** reads network packets from PCAP files, analyzes TCP/UDP traffic, distributes packets across multiple workers, and generates processing statistics and output PCAP files.

It demonstrates practical concepts such as **networking, packet processing, multithreading, load balancing, and monitoring**.

## ✨ Features

- 📂 PCAP file processing
- 🔍 TCP & UDP packet analysis
- 🧵 Multi-threaded packet processing
- ⚖️ Load balancing across workers
- ⚡ Fast-path packet processing
- 📊 Packet processing statistics
- 📤 Output PCAP generation
- 📈 Prometheus & Grafana monitoring

## 🏗️ Architecture

```text
              ┌─────────────┐
              │  PCAP File  │
              └──────┬──────┘
                     ↓
             ┌───────────────┐
             │ Packet Reader │
             └───────┬───────┘
                     ↓
             ┌───────────────┐
             │ Packet Parser │
             └───────┬───────┘
                     ↓
             ┌───────────────┐
             │ Load Balancer │
             └───────┬───────┘
                     ↓
          ┌──────────┼──────────┐
          ↓          ↓          ↓
       Worker 1   Worker 2   Worker N
          └──────────┼──────────┘
                     ↓
             ┌───────────────┐
             │   Processing  │
             └───────┬───────┘
                     ↓
          ┌──────────┴──────────┐
          ↓                     ↓
    Output PCAP             Statistics
```

## Project Structure
```
Packet-Inspector/
├── src/
│   └── main/
│       └── java/
│           └── packet_analyzer/
├── monitoring/
├── pom.xml
└── README.md
```
## 🚀 Get Started

1. Clone the Repository
```
git clone https://github.com/Rohan-src/Packet-Inspector.git
cd Packet-Inspector
```
2. Build the Project
```
mvn clean package
```
3. Run the Application
```
java -jar target/<jar-name>.jar
```
Replace <jar-name> with the JAR generated inside the target directory.

## 📊 Monitoring
The project includes monitoring support using Prometheus and Grafana.

Monitoring configuration is available in:
```
monitoring/
```
If Docker Compose is configured, start the monitoring services with:
```
docker compose up
```
## 🎯 Project Goal

The goal of Packet Inspector is to demonstrate how network packets can be efficiently processed using Java, multithreading, and load balancing.
```
⚠️ Note
Only analyze network traffic that you own or have permission to inspect.
```
