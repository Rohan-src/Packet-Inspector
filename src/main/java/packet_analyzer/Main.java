package packet_analyzer;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.*;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            return;
        }
        String input = args[0], output = args[1];
        int lbs = 2, fps = 2;
        List<String> ips = new ArrayList<>(), apps = new ArrayList<>(), doms = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip" -> {
                    if (i + 1 < args.length) ips.add(args[++i]);
                }
                case "--block-app" -> {
                    if (i + 1 < args.length) apps.add(args[++i]);
                }
                case "--block-domain" -> {
                    if (i + 1 < args.length) doms.add(args[++i]);
                }
                case "--lbs" -> {
                    if (i + 1 < args.length) lbs = Integer.parseInt(args[++i]);
                }
                case "--fps" -> {
                    if (i + 1 < args.length) fps = Integer.parseInt(args[++i]);
                }
            }
        }
        Engine e = new Engine(lbs, fps);
        ips.forEach(e::blockIP);
        apps.forEach(e::blockApp);
        doms.forEach(e::blockDomain);
        if (!e.process(input, output)) System.exit(1);
        System.out.println("\nOutput written to: " + output);
    }

    static void usage() {
        System.out.println("DPI Engine v2.0 - Multi-threaded Deep Packet Inspection\nUsage: java packet_analyzer.Main <input.pcap> <output.pcap> [options]\n  --block-ip <ip>\n  --block-app <app>\n  --block-domain <dom>\n  --lbs <n>\n  --fps <n>");
    }

    static final class Packet {
        long id, tsSec, tsUsec;
        Types.FiveTuple tuple = new Types.FiveTuple();
        byte[] data;
        int tcpFlags, payloadOffset, payloadLength;
    }

    static final class Flow {
        Types.FiveTuple tuple;
        Types.AppType app = Types.AppType.UNKNOWN;
        String sni = "";
        long packets, bytes;
        boolean blocked, classified;
    }

    static final class Rules {
        final Set<Long> ips = Collections.synchronizedSet(new HashSet<>());
        final Set<Types.AppType> apps = Collections.synchronizedSet(new HashSet<>());
        final List<String> domains = Collections.synchronizedList(new ArrayList<>());

        void blockIP(String x) {
            ips.add(Types.parseIP(x));
            System.out.println("[Rules] Blocked IP: " + x);
        }

        void blockApp(String x) {
            for (Types.AppType a : Types.AppType.values())
                if (a != Types.AppType.APP_COUNT && Types.appTypeToString(a).equals(x)) {
                    apps.add(a);
                    System.out.println("[Rules] Blocked app: " + x);
                    return;
                }
            System.err.println("[Rules] Unknown app: " + x);
        }

        void blockDomain(String x) {
            domains.add(x);
            System.out.println("[Rules] Blocked domain: " + x);
        }

        boolean isBlocked(long ip, Types.AppType a, String s) {
            if (ips.contains(ip) || apps.contains(a)) return true;
            for (String d : domains) if (s.contains(d)) return true;
            return false;
        }
    }

    static final class Stats {
        final AtomicLong total = new AtomicLong(), bytes = new AtomicLong(), forwarded = new AtomicLong(), dropped = new AtomicLong(), tcp = new AtomicLong(), udp = new AtomicLong();
        final Object lock = new Object();
        final Map<Types.AppType, Long> apps = new HashMap<>();
        final Map<String, Types.AppType> snis = new HashMap<>();

        void record(Types.AppType a, String s) {
            synchronized (lock) {
                apps.merge(a, 1L, Long::sum);
                if (!s.isEmpty()) snis.put(s, a);
            }
        }
    }

    static final class FastPath implements Runnable {
        final int id;
        final Rules rules;
        final Stats stats;
        final Queue<Packet> out;
        final Queue<Packet> in = new Queue<>();
        final Map<Types.FiveTuple, Flow> flows = new HashMap<>();
        final AtomicLong processed = new AtomicLong();
        volatile boolean running;
        Thread t;

        FastPath(int i, Rules r, Stats s, Queue<Packet> o) {
            id = i;
            rules = r;
            stats = s;
            out = o;
        }

        void start() {
            running = true;
            t = new Thread(this, "FP" + id);
            t.start();
        }

        void stop() {
            running = false;
            in.shutdown();
            try {
                if (t != null) t.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        public void run() {
            while (running) {
                Optional<Packet> po = in.pop(100);
                if (po.isEmpty()) continue;
                Packet p = po.get();
                processed.incrementAndGet();
                Flow f = flows.computeIfAbsent(p.tuple, k -> {
                    Flow z = new Flow();
                    z.tuple = k;
                    return z;
                });
                f.packets++;
                f.bytes += p.data.length;
                if (!f.classified) classify(p, f);
                if (!f.blocked) f.blocked = rules.isBlocked(p.tuple.srcIp, f.app, f.sni);
                stats.record(f.app, f.sni);
                if (f.blocked) stats.dropped.incrementAndGet();
                else {
                    stats.forwarded.incrementAndGet();
                    out.push(p);
                }
            }
        }

        void classify(Packet p, Flow f) {
            if (p.tuple.dstPort == 443 && p.payloadLength > 5) {
                Optional<String> s = Extractors.sni(p.data, p.payloadOffset, p.payloadLength);
                if (s.isPresent()) {
                    f.sni = s.get();
                    f.app = Types.sniToAppType(f.sni);
                    f.classified = true;
                    return;
                }
            }
            if (p.tuple.dstPort == 80 && p.payloadLength > 10) {
                Optional<String> s = Extractors.httpHost(p.data, p.payloadOffset, p.payloadLength);
                if (s.isPresent()) {
                    f.sni = s.get();
                    f.app = Types.sniToAppType(f.sni);
                    f.classified = true;
                    return;
                }
            }
            if (p.tuple.dstPort == 53 || p.tuple.srcPort == 53) {
                f.app = Types.AppType.DNS;
                f.classified = true;
                return;
            }
            if (p.tuple.dstPort == 443) f.app = Types.AppType.HTTPS;
            else if (p.tuple.dstPort == 80) f.app = Types.AppType.HTTP;
        }
    }

    static final class LoadBalancer implements Runnable {
        final int id;
        final List<FastPath> fps;
        final Queue<Packet> in = new Queue<>();
        final AtomicLong dispatched = new AtomicLong();
        volatile boolean running;
        Thread t;

        LoadBalancer(int i, List<FastPath> f) {
            id = i;
            fps = f;
        }

        void start() {
            running = true;
            t = new Thread(this, "LB" + id);
            t.start();
        }

        void stop() {
            running = false;
            in.shutdown();
            try {
                if (t != null) t.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        public void run() {
            while (running) {
                Optional<Packet> po = in.pop(100);
                if (po.isEmpty()) continue;
                Packet p = po.get();
                int idx = (int) Math.floorMod(p.tuple.hash64(), fps.size());
                fps.get(idx).in.push(p);
                dispatched.incrementAndGet();
            }
        }
    }

    static final class Engine {
        final int numLbs, fpsPerLb;
        final Rules rules = new Rules();
        final Stats stats = new Stats();
        final Queue<Packet> out = new Queue<>();
        final List<FastPath> fps = new ArrayList<>();
        final List<LoadBalancer> lbs = new ArrayList<>();

        Engine(int l, int f) {
            numLbs = l;
            fpsPerLb = f;
            System.out.println("\n╔══════════════════════════════════════════════════════════════╗\n║              DPI ENGINE v2.0 (Multi-threaded)                 ║\n╠══════════════════════════════════════════════════════════════╣\n║ Load Balancers: " + String.format("%2d", l) + "    FPs per LB: " + String.format("%2d", f) + "    Total FPs: " + String.format("%2d", l * f) + "     ║\n╚══════════════════════════════════════════════════════════════╝\n");
            for (int i = 0; i < l * f; i++) fps.add(new FastPath(i, rules, stats, out));
            for (int lb = 0; lb < l; lb++) {
                List<FastPath> x = new ArrayList<>();
                for (int i = 0; i < f; i++) x.add(fps.get(lb * f + i));
                lbs.add(new LoadBalancer(lb, x));
            }
        }

        void blockIP(String x) {
            rules.blockIP(x);
        }

        void blockApp(String x) {
            rules.blockApp(x);
        }

        void blockDomain(String x) {
            rules.blockDomain(x);
        }

        boolean process(String input, String outputFile) throws IOException {
            Pcap.Reader r = new Pcap.Reader();
            if (!r.open(input)) return false;
            FileOutputStream outFile;
            try {
                outFile = new FileOutputStream(outputFile);
            } catch (IOException e) {
                System.err.println("Cannot open output file");
                return false;
            }
            outFile.write(r.getGlobalHeader().toBytes());
            for (FastPath f : fps) f.start();
            for (LoadBalancer l : lbs) l.start();
            AtomicBoolean outputRunning = new AtomicBoolean(true);
            Thread writer = new Thread(() -> {
                while (outputRunning.get() || out.size() > 0) {
                    Optional<Packet> po = out.pop(50);
                    if (po.isEmpty()) continue;
                    try {
                        Packet p = po.get();
                        outFile.write(new Pcap.PacketHeader(p.tsSec, p.tsUsec, p.data.length, p.data.length).toBytes());
                        outFile.write(p.data);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }, "OutputWriter");
            writer.start();
            System.out.println("[Reader] Processing packets...");
            Pcap.RawPacket raw = new Pcap.RawPacket();
            PacketParser.Parsed parsed = new PacketParser.Parsed();
            long id = 0;
            while (r.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) continue;
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;
                Packet p = new Packet();
                p.id = id++;
                p.tsSec = raw.header.tsSec;
                p.tsUsec = raw.header.tsUsec;
                p.tcpFlags = parsed.tcpFlags;
                p.data = raw.data;
                p.tuple.srcIp = Types.parseIP(parsed.srcIp);
                p.tuple.dstIp = Types.parseIP(parsed.destIp);
                p.tuple.srcPort = parsed.srcPort;
                p.tuple.dstPort = parsed.destPort;
                p.tuple.protocol = parsed.protocol;
                p.payloadOffset = 14;
                if (p.data.length > 14) {
                    p.payloadOffset += (p.data[14] & 15) * 4;
                    if (parsed.hasTcp && p.payloadOffset + 12 < p.data.length)
                        p.payloadOffset += ((p.data[p.payloadOffset + 12] & 255) >>> 4) * 4;
                    else if (parsed.hasUdp) p.payloadOffset += 8;
                    p.payloadLength = Math.max(0, p.data.length - p.payloadOffset);
                }
                stats.total.incrementAndGet();
                stats.bytes.addAndGet(p.data.length);
                if (parsed.hasTcp) stats.tcp.incrementAndGet();
                else if (parsed.hasUdp) stats.udp.incrementAndGet();
                int lb = (int) Math.floorMod(p.tuple.hash64(), lbs.size());
                lbs.get(lb).in.push(p);
            }
            System.out.println("[Reader] Done reading " + id + " packets");
            r.close();
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            for (LoadBalancer l : lbs) l.stop();
            for (FastPath f : fps) f.stop();
            outputRunning.set(false);
            out.shutdown();
            try {
                writer.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            outFile.close();
            printReport();
            return true;
        }

        void printReport() {
            System.out.println("\n╔══════════════════════════════════════════════════════════════╗\n║                      PROCESSING REPORT                        ║\n╠══════════════════════════════════════════════════════════════╣");
            System.out.printf("║ Total Packets:      %12d                           ║%n", stats.total.get());
            System.out.printf("║ Total Bytes:        %12d                           ║%n", stats.bytes.get());
            System.out.printf("║ TCP Packets:        %12d                           ║%n", stats.tcp.get());
            System.out.printf("║ UDP Packets:        %12d                           ║%n", stats.udp.get());
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.printf("║ Forwarded:          %12d                           ║%n", stats.forwarded.get());
            System.out.printf("║ Dropped:            %12d                           ║%n", stats.dropped.get());
            System.out.println("╠══════════════════════════════════════════════════════════════╣\n║ THREAD STATISTICS                                             ║");
            for (LoadBalancer l : lbs)
                System.out.printf("║   LB%d dispatched:   %12d                           ║%n", l.id, l.dispatched.get());
            for (FastPath f : fps)
                System.out.printf("║   FP%d processed:    %12d                           ║%n", f.id, f.processed.get());
            System.out.println("╠══════════════════════════════════════════════════════════════╣\n║                   APPLICATION BREAKDOWN                       ║\n╠══════════════════════════════════════════════════════════════╣");
            List<Map.Entry<Types.AppType, Long>> a;
            synchronized (stats.lock) {
                a = new ArrayList<>(stats.apps.entrySet());
            }
            a.sort((x, y) -> Long.compare(y.getValue(), x.getValue()));
            for (var e : a) {
                double pct = stats.total.get() > 0 ? 100.0 * e.getValue() / stats.total.get() : 0;
                int bar = (int) (pct / 5);
                System.out.printf("║ %-15s%8d %5.1f%% %-20s  ║%n", Types.appTypeToString(e.getKey()), e.getValue(), pct, "#".repeat(bar));
            }
            System.out.println("╚══════════════════════════════════════════════════════════════╝");
            synchronized (stats.lock) {
                if (!stats.snis.isEmpty()) {
                    System.out.println("\n[Detected Domains/SNIs]");
                    for (var e : stats.snis.entrySet())
                        System.out.println("  - " + e.getKey() + " -> " + Types.appTypeToString(e.getValue()));
                }
            }
        }
    }
}
