# Packet_analyzer - Java conversion

This is a Java 17 conversion of the original C++ Packet_analyzer/DPI Engine. The processing flow and rules are kept the same: PCAP read -> Ethernet/IPv4/TCP/UDP parsing -> five-tuple -> SNI/HTTP/DNS classification -> blocking -> PCAP output -> report. The multi-threaded version keeps Reader -> LB -> FP -> Output architecture.

## Build
`mvn package`

## Multi-threaded run
`java -cp target/classes packet_analyzer.Main input.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook --lbs 2 --fps 2`

## Simple run
`java -cp target/classes packet_analyzer.MainSimple input.pcap output.pcap --block-app YouTube`

No external runtime library is required; PCAP parsing is implemented directly, matching the original project rather than replacing it with a packet-capture library.
