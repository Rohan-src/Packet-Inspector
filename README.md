# Packet Inspector — Multi-Threaded Network Packet Analyzer

A Java-based multi-threaded network packet analyzer that reads PCAP files, processes network packets, and generates useful packet statistics.

🚀 Features

📂 Read and process PCAP files

🔍 Analyze network packets

🌐 Support for TCP and UDP traffic

🧵 Multi-threaded packet processing

⚖️ Load balancing between workers

📊 Packet processing statistics

📤 Generate output PCAP files

📈 Monitoring with Prometheus and Grafana

🛠️ Technologies

Java 17

Maven

PCAP

Multithreading

Prometheus

Grafana

Docker

🔄 How It Works
PCAP File
    ↓
Packet Reader
    ↓
Packet Parser
    ↓
Load Balancer
    ↓
Multiple Workers
    ↓
Packet Processing
    ↓
Output PCAP + Statistics

▶️ Run
Clone the repository
git clone https://github.com/Rohan-src/Packet-Inspector.git
cd Packet-Inspector

Build
mvn clean package

Run

Run the generated JAR from the target directory:

java -jar target/<jar-name>.jar

📁 Project Structure
Packet-Inspector/
├── src/
│   └── main/
│       └── java/
│           └── packet_analyzer/
├── monitoring/
├── pom.xml
└── README.md

🎯 Purpose

This project demonstrates how network packets can be analyzed and processed efficiently using Java multithreading and load balancing.

⚠️ Only analyze network traffic that you own or have permission to inspect.

