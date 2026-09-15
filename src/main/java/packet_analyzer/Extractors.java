package packet_analyzer;

import java.nio.charset.StandardCharsets;
import java.util.*;

public final class Extractors {
    private Extractors() {
    }

    public static Optional<String> sni(byte[] p, int off, int len) {
        if (!isTls(p, off, len)) return Optional.empty();
        int x = off + 5;
        x += 4;
        x += 2;
        x += 32;
        if (x >= off + len) return Optional.empty();
        int sid = p[x] & 255;
        x += 1 + sid;
        if (x + 2 > off + len) return Optional.empty();
        int cs = PacketParser.u16(p, x);
        x += 2 + cs;
        if (x >= off + len) return Optional.empty();
        int comp = p[x] & 255;
        x += 1 + comp;
        if (x + 2 > off + len) return Optional.empty();
        int extLen = PacketParser.u16(p, x);
        x += 2;
        int end = Math.min(x + extLen, off + len);
        while (x + 4 <= end) {
            int type = PacketParser.u16(p, x), el = PacketParser.u16(p, x + 2);
            x += 4;
            if (x + el > end) break;
            if (type == 0) {
                if (el < 5) break;
                int list = PacketParser.u16(p, x);
                if (list < 3) break;
                int st = p[x + 2] & 255;
                int sl = PacketParser.u16(p, x + 3);
                if (st != 0 || sl > el - 5) break;
                return Optional.of(new String(p, x + 5, sl, StandardCharsets.ISO_8859_1));
            }
            x += el;
        }
        return Optional.empty();
    }

    public static boolean isTls(byte[] p, int off, int len) {
        if (len < 9) return false;
        int b = p[off] & 255;
        if (b != 0x16) return false;
        int v = PacketParser.u16(p, off + 1);
        if (v < 0x0300 || v > 0x0304) return false;
        int rl = PacketParser.u16(p, off + 3);
        if (rl > len - 5) return false;
        return (p[off + 5] & 255) == 1;
    }

    public static Optional<String> httpHost(byte[] p, int off, int len) {
        if (!httpRequest(p, off, len)) return Optional.empty();
        for (int i = 0; i + 6 < len; i++) {
            int x = off + i;
            if (eq4(p, x, 'H', 'o', 's', 't') || eq4(p, x, 'h', 'o', 's', 't')) {
                if ((p[x + 4] & 255) != ':') continue;
                int st = i + 5;
                while (st < len && (p[off + st] == ' ' || p[off + st] == '\t')) st++;
                int e = st;
                while (e < len && p[off + e] != '\r' && p[off + e] != '\n') e++;
                if (e > st) {
                    String host = new String(p, off + st, e - st, StandardCharsets.ISO_8859_1);
                    int c = host.indexOf(':');
                    if (c >= 0) host = host.substring(0, c);
                    return Optional.of(host);
                }
            }
        }
        return Optional.empty();
    }

    private static boolean eq4(byte[] p, int o, char a, char b, char c, char d) {
        return (p[o] & 255) == a && (p[o + 1] & 255) == b && (p[o + 2] & 255) == c && (p[o + 3] & 255) == d;
    }

    public static boolean httpRequest(byte[] p, int off, int len) {
        if (len < 4) return false;
        String[] m = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        for (String s : m) {
            byte[] q = s.getBytes(StandardCharsets.ISO_8859_1);
            boolean ok = true;
            for (int i = 0; i < 4; i++)
                if ((p[off + i] & 255) != (q[i] & 255)) {
                    ok = false;
                    break;
                }
            if (ok) return true;
        }
        return false;
    }

    public static boolean dnsQuery(byte[] p, int off, int len) {
        if (len < 12) return false;
        if ((p[off + 2] & 0x80) != 0) return false;
        return PacketParser.u16(p, off + 4) > 0;
    }

    public static Optional<String> dnsDomain(byte[] p, int off, int len) {
        if (!dnsQuery(p, off, len)) return Optional.empty();
        int x = 12;
        StringBuilder d = new StringBuilder();
        while (x < len) {
            int n = p[off + x] & 255;
            if (n == 0) break;
            if (n > 63) break;
            x++;
            if (x + n > len) break;
            if (d.length() > 0) d.append('.');
            d.append(new String(p, off + x, n, StandardCharsets.ISO_8859_1));
            x += n;
        }
        return d.length() == 0 ? Optional.empty() : Optional.of(d.toString());
    }

    public static boolean quicInitial(byte[] p, int off, int len) {
        if (len < 5) return false;
        return (p[off] & 0x80) != 0;
    }

    public static Optional<String> quicSni(byte[] p, int off, int len) {
        if (!quicInitial(p, off, len)) return Optional.empty();
        for (int i = 0; i + 50 < len; i++)
            if ((p[off + i] & 255) == 1) {
                int start = i - 5;
                if (start >= 0) {
                    Optional<String> r = sni(p, off + start, len - start);
                    if (r.isPresent()) return r;
                }
            }
        return Optional.empty();
    }
}
