using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;

class Lookup {
    record Feed(
        string Name, byte BaseScore, byte Confidence,
        uint FlagsMask, byte CategoriesMask,
        ulong[] IPv4Starts, ulong[] IPv4Ends
    );

    record Blocklist(
        uint Timestamp, string[] Flags, string[] Categories,
        Feed[] Feeds
    );

    static ulong ReadVarint(BinaryReader r) {
        ulong result = 0; int shift = 0;
        while (true) {
            byte b = r.ReadByte();
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return result;
            shift += 7;
        }
    }

    static string ReadStr(BinaryReader r) {
        byte len = r.ReadByte();
        return System.Text.Encoding.UTF8.GetString(r.ReadBytes(len));
    }

    static Blocklist Load(string path) {
        using var r = new BinaryReader(File.OpenRead(path));
        if (new string(r.ReadChars(4)) != "IPBL")
            throw new Exception("invalid magic");
        if (r.ReadByte() != 2) throw new Exception("bad version");
        uint timestamp = r.ReadUInt32();

        int flagCount = r.ReadByte();
        var flags = new string[flagCount];
        for (int i = 0; i < flagCount; i++) flags[i] = ReadStr(r);

        int catCount = r.ReadByte();
        var cats = new string[catCount];
        for (int i = 0; i < catCount; i++) cats[i] = ReadStr(r);

        int feedCount = r.ReadUInt16();
        var feeds = new Feed[feedCount];

        for (int i = 0; i < feedCount; i++) {
            string name = ReadStr(r);
            byte bs = r.ReadByte(), co = r.ReadByte();
            uint fm = r.ReadUInt32();
            byte cm = r.ReadByte();
            uint rc = r.ReadUInt32();

            var v4s = new List<ulong>();
            var v4e = new List<ulong>();
            ulong current = 0;

            for (uint j = 0; j < rc; j++) {
                current += ReadVarint(r);
                ulong size = ReadVarint(r);
                ulong end = current + size;
                if (end <= 0xFFFFFFFF) {
                    v4s.Add(current); v4e.Add(end);
                }
            }

            feeds[i] = new Feed(
                name, bs, co, fm, cm,
                v4s.ToArray(), v4e.ToArray()
            );
        }

        return new Blocklist(timestamp, flags, cats, feeds);
    }

    static int BisectRight(ulong[] arr, ulong target) {
        int lo = 0, hi = arr.Length;
        while (lo < hi) {
            int mid = lo + (hi - lo) / 2;
            if (arr[mid] <= target) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    static void Main(string[] args) {
        if (args.Length < 1) {
            Console.Error.WriteLine("Usage: lookup <ip> [<ip> ...]");
            return;
        }

        var bl = Load("blocklist.bin");

        foreach (var ip in args) {
            if (!IPAddress.TryParse(ip, out var addr)) {
                Console.WriteLine($"{ip}: invalid IP");
                continue;
            }

            if (addr.AddressFamily != AddressFamily.InterNetwork) {
                Console.WriteLine($"{ip}: IPv6 not supported");
                continue;
            }

            byte[] bytes = addr.GetAddressBytes();
            ulong target = ((ulong)bytes[0] << 24)
                | ((ulong)bytes[1] << 16)
                | ((ulong)bytes[2] << 8) | bytes[3];

            bool found = false;
            foreach (var f in bl.Feeds) {
                int idx = BisectRight(f.IPv4Starts, target) - 1;
                if (idx >= 0 && target <= f.IPv4Ends[idx]) {
                    double score = (f.BaseScore / 200.0)
                                 * (f.Confidence / 200.0);
                    var parts = new List<string> {
                        f.Name, $"score={score:F2}"
                    };

                    var fl = new List<string>();
                    for (int i = 0; i < bl.Flags.Length; i++)
                        if ((f.FlagsMask & (1u << i)) != 0)
                            fl.Add(bl.Flags[i]);
                    if (fl.Count > 0)
                        parts.Add("flags=" + string.Join(",", fl));

                    var ca = new List<string>();
                    for (int i = 0; i < bl.Categories.Length; i++)
                        if ((f.CategoriesMask & (1 << i)) != 0)
                            ca.Add(bl.Categories[i]);
                    if (ca.Count > 0)
                        parts.Add("cats=" + string.Join(",", ca));

                    Console.WriteLine(
                        $"{ip}: {string.Join(" | ", parts)}"
                    );
                    found = true;
                }
            }

            if (!found) Console.WriteLine($"{ip}: no matches");
        }
    }
}
