package packet_analyzer;

public final class PacketParser {
    public static final int IPV4 = 0x0800, TCP = 6, UDP = 17;

    private PacketParser() {
    }

    public static boolean parse(Pcap.RawPacket raw, Parsed p) {
        p.timestampSec = raw.header.tsSec;
        p.timestampUsec = raw.header.tsUsec;
        p.hasIp = false;
        p.hasTcp = false;
        p.hasUdp = false;
        p.payloadOffset = 0;
        p.payloadLength = 0;
        byte[] d = raw.data;
        int len = d.length, off = 0;
        if (!parseEthernet(d, len, p, off)) return false;
        off = 14;
        if (p.etherType == IPV4) {
            int[] o = {off};
            if (!parseIPv4(d, len, p, o)) return false;
            off = o[0];
            if (p.protocol == TCP) {
                if (!parseTCP(d, len, p, o)) return false;
                off = o[0];
            } else if (p.protocol == UDP) {
                if (!parseUDP(d, len, p, o)) return false;
                off = o[0];
            }
        }
        p.payloadOffset = off;
        p.payloadLength = Math.max(0, len - off);
        return true;
    }

    private static boolean parseEthernet(byte[] d, int len, Parsed p, int off) {
        if (len < 14) return false;
        p.destMac = macToString(d, 0);
        p.srcMac = macToString(d, 6);
        p.etherType = u16(d, 12);
        return true;
    }

    private static boolean parseIPv4(byte[] d, int len, Parsed p, int[] off) {
        int o = off[0];
        if (len < o + 20) return false;
        int vi = d[o] & 255;
        p.ipVersion = (vi >>> 4) & 15;
        int ihl = vi & 15;
        if (p.ipVersion != 4) return false;
        int h = ihl * 4;
        if (h < 20 || len < o + h) return false;
        p.ttl = d[o + 8] & 255;
        p.protocol = d[o + 9] & 255;
        p.srcIp = ipToString(u32(d, o + 12));
        p.destIp = ipToString(u32(d, o + 16));
        p.hasIp = true;
        off[0] = o + h;
        return true;
    }

    private static boolean parseTCP(byte[] d, int len, Parsed p, int[] off) {
        int o = off[0];
        if (len < o + 20) return false;
        p.srcPort = u16(d, o);
        p.destPort = u16(d, o + 2);
        p.seqNumber = u32(d, o + 4);
        p.ackNumber = u32(d, o + 8);
        int dataOffset = ((d[o + 12] & 255) >>> 4) & 15;
        int h = dataOffset * 4;
        p.tcpFlags = d[o + 13] & 255;
        if (h < 20 || len < o + h) return false;
        p.hasTcp = true;
        off[0] = o + h;
        return true;
    }

    private static boolean parseUDP(byte[] d, int len, Parsed p, int[] off) {
        int o = off[0];
        if (len < o + 8) return false;
        p.srcPort = u16(d, o);
        p.destPort = u16(d, o + 2);
        p.hasUdp = true;
        off[0] = o + 8;
        return true;
    }

    public static int u16(byte[] d, int o) {
        return ((d[o] & 255) << 8) | (d[o + 1] & 255);
    }

    public static long u32(byte[] d, int o) {
        return ((long) (d[o] & 255) << 24) | ((long) (d[o + 1] & 255) << 16) | ((long) (d[o + 2] & 255) << 8) | (d[o + 3] & 255);
    }

    public static String macToString(byte[] d, int o) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) s.append(':');
            s.append(String.format("%02x", d[o + i] & 255));
        }
        return s.toString();
    }

    public static String ipToString(long ip) {
        return ((ip >>> 24) & 255) + "." + ((ip >>> 16) & 255) + "." + ((ip >>> 8) & 255) + "." + (ip & 255);
    }

    public static final class Parsed {
        public long timestampSec, timestampUsec;
        public String srcMac, destMac;
        public int etherType;
        public boolean hasIp;
        public int ipVersion;
        public String srcIp, destIp;
        public int protocol, ttl;
        public boolean hasTcp, hasUdp;
        public int srcPort, destPort;
        public int tcpFlags;
        public long seqNumber, ackNumber;
        public int payloadLength, payloadOffset;
    }
}
