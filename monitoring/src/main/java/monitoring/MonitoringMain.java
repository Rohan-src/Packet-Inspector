package monitoring;

import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.exporter.HTTPServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Monitoring-only launcher. The original packet_analyzer source is not modified.
 * It runs packet_analyzer.Main as a child process, reads its existing report,
 * and publishes those values to Prometheus.
 */
public class MonitoringMain {
    private static final Counter RUNS = Counter.build().name("packet_analyzer_runs_total").help("Number of packet analyzer runs started through MonitoringMain").register();

    private static final Gauge TOTAL_PACKETS = Gauge.build().name("packet_analyzer_packets").help("Total packets processed in the current run").register();

    private static final Gauge TOTAL_BYTES = Gauge.build().name("packet_analyzer_bytes").help("Total bytes processed in the current run").register();

    private static final Gauge TCP_PACKETS = Gauge.build().name("packet_analyzer_tcp_packets").help("TCP packets processed in the current run").register();

    private static final Gauge UDP_PACKETS = Gauge.build().name("packet_analyzer_udp_packets").help("UDP packets processed in the current run").register();

    private static final Gauge FORWARDED = Gauge.build().name("packet_analyzer_forwarded_packets").help("Packets forwarded in the current run").register();

    private static final Gauge DROPPED = Gauge.build().name("packet_analyzer_dropped_packets").help("Packets dropped in the current run").register();

    private static final Gauge LB_DISPATCHED = Gauge.build().labelNames("load_balancer").name("packet_analyzer_lb_dispatched").help("Packets dispatched by each load balancer").register();

    private static final Gauge FP_PROCESSED = Gauge.build().labelNames("fast_path").name("packet_analyzer_fp_processed").help("Packets processed by each fast path").register();

    private static final Pattern NUMBER = Pattern.compile("(-?\\d+)");

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: MonitoringMain <input.pcap> <output.pcap> [Main options]");
            return;
        }

        HTTPServer server = new HTTPServer(9400);
        System.out.println("Prometheus metrics: http://localhost:9400/metrics");
        RUNS.inc();

        List<String> command = new ArrayList<>();
        command.add(javaExecutable());
        command.add("-cp");

        String currentClasspath = System.getProperty("java.class.path");
        String originalClasses = new java.io.File("target/classes").getAbsolutePath();

        String combinedClasspath = originalClasses + java.io.File.pathSeparator + currentClasspath;

        command.add(combinedClasspath);
        command.add("packet_analyzer.Main");

        for (String arg : args) {
            command.add(arg);
        }

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
                parseLine(line);
            }
        }

        int exit = process.waitFor();
        System.out.println("Packet analyzer finished with exit code: " + exit);
        System.out.println("Grafana can read these metrics through Prometheus while this monitoring process is running.");

        // Keep the exporter available after the packet analyzer finishes.
        Thread.currentThread().join();
    }

    private static String javaExecutable() {
        String home = System.getProperty("java.home");
        String sep = System.getProperty("file.separator");
        return home + sep + "bin" + sep + "java";
    }

    private static void parseLine(String line) {
        if (line.contains("Total Packets:")) TOTAL_PACKETS.set(numberAfterColon(line));
        else if (line.contains("Total Bytes:")) TOTAL_BYTES.set(numberAfterColon(line));
        else if (line.contains("TCP Packets:")) TCP_PACKETS.set(numberAfterColon(line));
        else if (line.contains("UDP Packets:")) UDP_PACKETS.set(numberAfterColon(line));
        else if (line.contains("Forwarded:")) FORWARDED.set(numberAfterColon(line));
        else if (line.contains("Dropped:")) DROPPED.set(numberAfterColon(line));
        else if (line.contains("dispatched:")) {
            String id = textAfter(line, "LB");
            if (id != null) LB_DISPATCHED.labels(id).set(numberAfterColon(line));
        } else if (line.contains("processed:")) {
            String id = textAfter(line, "FP");
            if (id != null) FP_PROCESSED.labels(id).set(numberAfterColon(line));
        }
    }

    private static String textAfter(String line, String marker) {
        int start = line.indexOf(marker);
        if (start < 0) return null;
        start += marker.length();
        int end = start;
        while (end < line.length() && Character.isDigit(line.charAt(end))) end++;
        return end > start ? line.substring(start, end) : null;
    }

    private static long numberAfterColon(String line) {
        int colon = line.indexOf(':');
        String value = colon >= 0 ? line.substring(colon + 1) : line;
        Matcher matcher = NUMBER.matcher(value);
        long result = 0;
        while (matcher.find()) result = Long.parseLong(matcher.group(1));
        return result;
    }
}
