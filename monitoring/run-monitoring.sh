#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mvn -q package
cd monitoring
mvn -q package dependency:copy-dependencies -DoutputDirectory=target/dependency
if [ "$#" -lt 2 ]; then
  echo "Usage: monitoring/run-monitoring.sh <input.pcap> <output.pcap> [Main options]"
  exit 1
fi
java -cp "../target/classes:target/classes:target/dependency/*" monitoring.MonitoringMain "$@"
