package packet_analyzer;

import java.io.*;
import java.util.*;

public class MainSimple {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java packet_analyzer.MainSimple <input.pcap> <output.pcap> [options]");
            return;
        }
        Rules rules = new Rules();
        for (int i = 2; i < args.length; i++) {
            if (args[i].equals("--block-ip") && i + 1 < args.length) rules.blockIP(args[++i]);
            else if (args[i].equals("--block-app") && i + 1 < args.length) rules.blockApp(args[++i]);
            else if (args[i].equals("--block-domain") && i + 1 < args.length) rules.blockDomain(args[++i]);
        }
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗\n║                    DPI ENGINE v1.0                            ║\n╚══════════════════════════════════════════════════════════════╝\n");
        Pcap.Reader r = new Pcap.Reader();
        if (!r.open(args[0])) System.exit(1);
        FileOutputStream out = new FileOutputStream(args[1]);
        out.write(r.getGlobalHeader().toBytes());
        Map<Types.FiveTuple, Flow> flows = new HashMap<>();
        long total = 0, forwarded = 0, dropped = 0;
        Map<Types.AppType, Long> stats = new HashMap<>();
        System.out.println("[DPI] Processing packets...");
        Pcap.RawPacket raw = new Pcap.RawPacket();
        PacketParser.Parsed p = new PacketParser.Parsed();
        while (r.readNextPacket(raw)) {
            total++;
            if (!PacketParser.parse(raw, p)) continue;
            if (!p.hasIp || (!p.hasTcp && !p.hasUdp)) continue;
            Types.FiveTuple t = new Types.FiveTuple();
            t.srcIp = Types.parseIP(p.srcIp);
            t.dstIp = Types.parseIP(p.destIp);
            t.srcPort = p.srcPort;
            t.dstPort = p.destPort;
            t.protocol = p.protocol;
            Flow f = flows.computeIfAbsent(t, k -> {
                Flow x = new Flow();
                x.tuple = k;
                return x;
            });
            f.packets++;
            f.bytes += raw.data.length;
            if ((f.app == Types.AppType.UNKNOWN || f.app == Types.AppType.HTTPS) && f.sni.isEmpty() && p.hasTcp && p.destPort == 443) {
                int po = 14;
                if (po < raw.data.length) {
                    po += (raw.data[14] & 15) * 4;
                    if (po + 12 < raw.data.length) po += ((raw.data[po + 12] & 255) >>> 4) * 4;
                    if (po < raw.data.length) {
                        int pl = raw.data.length - po;
                        if (pl > 5) {
                            var s = Extractors.sni(raw.data, po, pl);
                            if (s.isPresent()) {
                                f.sni = s.get();
                                f.app = Types.sniToAppType(f.sni);
                            }
                        }
                    }
                }
            }
            if ((f.app == Types.AppType.UNKNOWN || f.app == Types.AppType.HTTP) && f.sni.isEmpty() && p.hasTcp && p.destPort == 80) {
                int po = 14;
                if (po < raw.data.length) {
                    po += (raw.data[14] & 15) * 4;
                    if (po + 12 < raw.data.length) po += ((raw.data[po + 12] & 255) >>> 4) * 4;
                    if (po < raw.data.length) {
                        var h = Extractors.httpHost(raw.data, po, raw.data.length - po);
                        if (h.isPresent()) {
                            f.sni = h.get();
                            f.app = Types.sniToAppType(f.sni);
                        }
                    }
                }
            }
            if (f.app == Types.AppType.UNKNOWN && (p.destPort == 53 || p.srcPort == 53)) f.app = Types.AppType.DNS;
            if (f.app == Types.AppType.UNKNOWN) {
                if (p.destPort == 443) f.app = Types.AppType.HTTPS;
                else if (p.destPort == 80) f.app = Types.AppType.HTTP;
            }
            if (!f.blocked) {
                f.blocked = rules.blocked(t.srcIp, f.app, f.sni);
                if (f.blocked)
                    System.out.println("[BLOCKED] " + p.srcIp + " -> " + p.destIp + " (" + Types.appTypeToString(f.app) + (f.sni.isEmpty() ? "" : ": " + f.sni) + ")");
            }
            stats.merge(f.app, 1L, Long::sum);
            if (f.blocked) dropped++;
            else {
                forwarded++;
                out.write(new Pcap.PacketHeader(raw.header.tsSec, raw.header.tsUsec, raw.data.length, raw.data.length).toBytes());
                out.write(raw.data);
            }
        }
        r.close();
        out.close();
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗\n║                      PROCESSING REPORT                       ║\n╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Total Packets:      %10d                             ║%n", total);
        System.out.printf("║ Forwarded:          %10d                             ║%n", forwarded);
        System.out.printf("║ Dropped:            %10d                             ║%n", dropped);
        System.out.printf("║ Active Flows:       %10d                             ║%n", flows.size());
        System.out.println("╠══════════════════════════════════════════════════════════════╣\n║                    APPLICATION BREAKDOWN                     ║\n╠══════════════════════════════════════════════════════════════╣");
        List<Map.Entry<Types.AppType, Long>> sorted = new ArrayList<>(stats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        for (var e : sorted) {
            double pct = 100.0 * e.getValue() / total;
            System.out.printf("║ %-15s%8d %5.1f%% %-20s  ║%n", Types.appTypeToString(e.getKey()), e.getValue(), pct, "#".repeat((int) (pct / 5)));
        }
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n\n[Detected Applications/Domains]");
        for (var e : flows.entrySet())
            if (!e.getValue().sni.isEmpty())
                System.out.println("  - " + e.getValue().sni + " -> " + Types.appTypeToString(e.getValue().app));
        System.out.println("\nOutput written to: " + args[1]);
    }

    static class Flow {
        Types.FiveTuple tuple;
        Types.AppType app = Types.AppType.UNKNOWN;
        String sni = "";
        long packets, bytes;
        boolean blocked;
    }

    static class Rules {
        Set<Long> ips = new HashSet<>();
        Set<Types.AppType> apps = new HashSet<>();
        List<String> domains = new ArrayList<>();

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

        boolean blocked(long ip, Types.AppType a, String s) {
            if (ips.contains(ip) || apps.contains(a)) return true;
            for (String d : domains) if (s.contains(d)) return true;
            return false;
        }
    }
}
