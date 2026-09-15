package packet_analyzer;

import java.util.*;

public final class Types {
    private Types() {
    }

    public static String appTypeToString(AppType t) {
        return switch (t) {
            case UNKNOWN -> "Unknown";
            case HTTP -> "HTTP";
            case HTTPS -> "HTTPS";
            case DNS -> "DNS";
            case TLS -> "TLS";
            case QUIC -> "QUIC";
            case GOOGLE -> "Google";
            case FACEBOOK -> "Facebook";
            case YOUTUBE -> "YouTube";
            case TWITTER -> "Twitter/X";
            case INSTAGRAM -> "Instagram";
            case NETFLIX -> "Netflix";
            case AMAZON -> "Amazon";
            case MICROSOFT -> "Microsoft";
            case APPLE -> "Apple";
            case WHATSAPP -> "WhatsApp";
            case TELEGRAM -> "Telegram";
            case TIKTOK -> "TikTok";
            case SPOTIFY -> "Spotify";
            case ZOOM -> "Zoom";
            case DISCORD -> "Discord";
            case GITHUB -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
            case APP_COUNT -> "Unknown";
        };
    }

    public static AppType sniToAppType(String s) {
        if (s == null || s.isEmpty()) return AppType.UNKNOWN;
        String x = s.toLowerCase(Locale.ROOT);
        if (x.contains("google") || x.contains("gstatic") || x.contains("googleapis") || x.contains("ggpht") || x.contains("gvt1"))
            return AppType.GOOGLE;
        if (x.contains("youtube") || x.contains("ytimg") || x.contains("youtu.be") || x.contains("yt3.ggpht"))
            return AppType.YOUTUBE;
        if (x.contains("facebook") || x.contains("fbcdn") || x.contains("fb.com") || x.contains("fbsbx") || x.contains("meta.com"))
            return AppType.FACEBOOK;
        if (x.contains("instagram") || x.contains("cdninstagram")) return AppType.INSTAGRAM;
        if (x.contains("whatsapp") || x.contains("wa.me")) return AppType.WHATSAPP;
        if (x.contains("twitter") || x.contains("twimg") || x.contains("x.com") || x.contains("t.co"))
            return AppType.TWITTER;
        if (x.contains("netflix") || x.contains("nflxvideo") || x.contains("nflximg")) return AppType.NETFLIX;
        if (x.contains("amazon") || x.contains("amazonaws") || x.contains("cloudfront") || x.contains("aws"))
            return AppType.AMAZON;
        if (x.contains("microsoft") || x.contains("msn.com") || x.contains("office") || x.contains("azure") || x.contains("live.com") || x.contains("outlook") || x.contains("bing"))
            return AppType.MICROSOFT;
        if (x.contains("apple") || x.contains("icloud") || x.contains("mzstatic") || x.contains("itunes"))
            return AppType.APPLE;
        if (x.contains("telegram") || x.contains("t.me")) return AppType.TELEGRAM;
        if (x.contains("tiktok") || x.contains("tiktokcdn") || x.contains("musical.ly") || x.contains("bytedance"))
            return AppType.TIKTOK;
        if (x.contains("spotify") || x.contains("scdn.co")) return AppType.SPOTIFY;
        if (x.contains("zoom")) return AppType.ZOOM;
        if (x.contains("discord") || x.contains("discordapp")) return AppType.DISCORD;
        if (x.contains("github") || x.contains("githubusercontent")) return AppType.GITHUB;
        if (x.contains("cloudflare") || x.contains("cf-")) return AppType.CLOUDFLARE;
        return AppType.HTTPS;
    }

    public static long parseIP(String ip) {
        long result = 0;
        int oct = 0, shift = 0;
        for (char c : ip.toCharArray()) {
            if (c == '.') {
                result |= ((long) oct << shift);
                shift += 8;
                oct = 0;
            } else if (c >= '0' && c <= '9') oct = oct * 10 + c - '0';
        }
        return result | ((long) oct << shift);
    }

    public enum AppType {UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC, GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM, NETFLIX, AMAZON, MICROSOFT, APPLE, WHATSAPP, TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE, APP_COUNT}

    public static final class FiveTuple {
        public long srcIp, dstIp;
        public int srcPort, dstPort, protocol;

        private static long combine(long h, long v) {
            return h ^ (v + 0x9e3779b9L + (h << 6) + (h >>> 2));
        }

        public static String ip(long ip) {
            return (ip & 255) + "." + ((ip >>> 8) & 255) + "." + ((ip >>> 16) & 255) + "." + ((ip >>> 24) & 255);
        }

        public FiveTuple reverse() {
            FiveTuple x = new FiveTuple();
            x.srcIp = dstIp;
            x.dstIp = srcIp;
            x.srcPort = dstPort;
            x.dstPort = srcPort;
            x.protocol = protocol;
            return x;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof FiveTuple x)) return false;
            return srcIp == x.srcIp && dstIp == x.dstIp && srcPort == x.srcPort && dstPort == x.dstPort && protocol == x.protocol;
        }

        @Override
        public int hashCode() {
            long h = 0;
            h = combine(h, srcIp);
            h = combine(h, dstIp);
            h = combine(h, srcPort);
            h = combine(h, dstPort);
            h = combine(h, protocol);
            return (int) (h ^ (h >>> 32));
        }

        public long hash64() {
            long h = 0;
            h = combine(h, srcIp);
            h = combine(h, dstIp);
            h = combine(h, srcPort);
            h = combine(h, dstPort);
            h = combine(h, protocol);
            return h;
        }

        public String toString() {
            return ip(srcIp) + ":" + srcPort + " -> " + ip(dstIp) + ":" + dstPort + " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
        }
    }
}
