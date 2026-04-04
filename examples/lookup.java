import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;

public class lookup {
    record Feed(
        String name, int baseScore, int confidence,
        int flagsMask, int categoriesMask,
        long[] ipv4Starts, long[] ipv4Ends,
        long[] ipv6Starts, long[] ipv6Ends
    ) {}

    record Blocklist(
        long timestamp, String[] flags, String[] categories,
        Feed[] feeds
    ) {}

    static int pos;

    static long readVarint(byte[] d) {
        long result = 0;
        int shift = 0;
        while (true) {
            int b = d[pos++] & 0xFF;
            result |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) return result;
            shift += 7;
        }
    }

    static String readStr(byte[] d) {
        int len = d[pos++] & 0xFF;
        String s = new String(d, pos, len);
        pos += len;
        return s;
    }

    static int readU16(byte[] d) {
        int v = (d[pos] & 0xFF) | ((d[pos + 1] & 0xFF) << 8);
        pos += 2;
        return v;
    }

    static long readU32(byte[] d) {
        long v = (d[pos] & 0xFFL) | ((d[pos+1] & 0xFFL) << 8)
               | ((d[pos+2] & 0xFFL) << 16)
               | ((d[pos+3] & 0xFFL) << 24);
        pos += 4;
        return v;
    }

    static Blocklist load(String path) throws IOException {
        byte[] d = Files.readAllBytes(Path.of(path));
        pos = 0;

        if (d[0] != 'I' || d[1] != 'P' || d[2] != 'B' || d[3] != 'L')
            throw new IOException("invalid magic");
        pos = 4;

        if (d[pos++] != 2) throw new IOException("bad version");
        long timestamp = readU32(d);

        int flagCount = d[pos++] & 0xFF;
        String[] flags = new String[flagCount];
        for (int i = 0; i < flagCount; i++) flags[i] = readStr(d);

        int catCount = d[pos++] & 0xFF;
        String[] cats = new String[catCount];
        for (int i = 0; i < catCount; i++) cats[i] = readStr(d);

        int feedCount = readU16(d);
        Feed[] feeds = new Feed[feedCount];

        for (int i = 0; i < feedCount; i++) {
            String name = readStr(d);
            int baseScore = d[pos++] & 0xFF;
            int confidence = d[pos++] & 0xFF;
            long fmask = readU32(d);
            int cmask = d[pos++] & 0xFF;
            long rangeCount = readU32(d);

            var v4s = new ArrayList<Long>();
            var v4e = new ArrayList<Long>();
            var v6s = new ArrayList<Long>();
            var v6e = new ArrayList<Long>();
            long current = 0;

            for (long r = 0; r < rangeCount; r++) {
                current += readVarint(d);
                long size = readVarint(d);
                long end = current + size;
                if (end <= 0xFFFFFFFFL) {
                    v4s.add(current);
                    v4e.add(end);
                } else {
                    v6s.add(current);
                    v6e.add(end);
                }
            }

            feeds[i] = new Feed(
                name, baseScore, confidence,
                (int) fmask, cmask,
                v4s.stream().mapToLong(Long::longValue).toArray(),
                v4e.stream().mapToLong(Long::longValue).toArray(),
                v6s.stream().mapToLong(Long::longValue).toArray(),
                v6e.stream().mapToLong(Long::longValue).toArray()
            );
        }

        return new Blocklist(timestamp, flags, cats, feeds);
    }

    static int bisectRight(long[] arr, long target) {
        int lo = 0, hi = arr.length;
        while (lo < hi) {
            int mid = lo + (hi - lo) / 2;
            if (arr[mid] <= target) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    static String formatMatch(Blocklist bl, Feed f) {
        double score = (f.baseScore / 200.0)
                     * (f.confidence / 200.0);
        var parts = new ArrayList<>(
            List.of(f.name, String.format("score=%.2f", score))
        );

        var matched = new StringJoiner(",");
        for (int i = 0; i < bl.flags.length; i++)
            if ((f.flagsMask & (1 << i)) != 0)
                matched.add(bl.flags[i]);
        if (matched.length() > 0)
            parts.add("flags=" + matched);

        var cats = new StringJoiner(",");
        for (int i = 0; i < bl.categories.length; i++)
            if ((f.categoriesMask & (1 << i)) != 0)
                cats.add(bl.categories[i]);
        if (cats.length() > 0)
            parts.add("cats=" + cats);

        return String.join(" | ", parts);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java lookup <ip> [<ip> ...]");
            System.exit(1);
        }

        Blocklist bl = load("blocklist.bin");

        for (String arg : args) {
            InetAddress addr;
            try {
                addr = InetAddress.getByName(arg);
            } catch (Exception e) {
                System.out.println(arg + ": invalid IP");
                continue;
            }

            boolean found = false;
            if (addr instanceof Inet4Address) {
                byte[] bytes = addr.getAddress();
                long target = ((bytes[0] & 0xFFL) << 24)
                    | ((bytes[1] & 0xFFL) << 16)
                    | ((bytes[2] & 0xFFL) << 8)
                    | (bytes[3] & 0xFFL);
                for (Feed f : bl.feeds) {
                    int idx = bisectRight(f.ipv4Starts, target) - 1;
                    if (idx >= 0 && target <= f.ipv4Ends[idx]) {
                        System.out.printf(
                            "%s: %s%n", arg, formatMatch(bl, f)
                        );
                        found = true;
                    }
                }
            }

            if (!found) System.out.println(arg + ": no matches");
        }
    }
}
