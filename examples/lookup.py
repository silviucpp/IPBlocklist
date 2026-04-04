import struct, sys, ipaddress
from bisect import bisect_right


def load(path="blocklist.bin"):
    with open(path, "rb") as f:
        assert f.read(4) == b"IPBL" and struct.unpack("<B", f.read(1))[0] == 2
        timestamp = struct.unpack("<I", f.read(4))[0]

        def read_varint():
            r, s = 0, 0
            while True:
                b = f.read(1)[0]
                r |= (b & 0x7F) << s
                if not (b & 0x80):
                    return r
                s += 7

        def read_str():
            n = f.read(1)[0]
            return f.read(n).decode()

        flags = [read_str() for _ in range(f.read(1)[0])]
        cats = [read_str() for _ in range(f.read(1)[0])]
        feed_count = struct.unpack("<H", f.read(2))[0]
        feeds = []

        for _ in range(feed_count):
            name = read_str()
            bs, co = f.read(1)[0], f.read(1)[0]
            fm = struct.unpack("<I", f.read(4))[0]
            cm = f.read(1)[0]
            rc = struct.unpack("<I", f.read(4))[0]
            v4s, v4e, v6s, v6e, cur = [], [], [], [], 0
            for _ in range(rc):
                cur += read_varint()
                end = cur + read_varint()
                if end <= 0xFFFFFFFF:
                    v4s.append(cur)
                    v4e.append(end)
                else:
                    v6s.append(cur)
                    v6e.append(end)
            feeds.append(
                {
                    "name": name,
                    "base_score": bs / 200.0,
                    "confidence": co / 200.0,
                    "flags": [flags[i] for i in range(len(flags)) if fm & (1 << i)],
                    "categories": [cats[i] for i in range(len(cats)) if cm & (1 << i)],
                    "v4s": tuple(v4s),
                    "v4e": tuple(v4e),
                    "v6s": tuple(v6s),
                    "v6e": tuple(v6e),
                }
            )
    return timestamp, feeds


def lookup(feeds, ip_str):
    addr = ipaddress.ip_address(ip_str)
    t = int(addr)
    for f in feeds:
        s, e = (f["v4s"], f["v4e"]) if addr.version == 4 else (f["v6s"], f["v6e"])
        i = bisect_right(s, t) - 1
        if i >= 0 and t <= e[i]:
            sc = f["base_score"] * f["confidence"]
            fl = ",".join(f["flags"])
            ca = ",".join(f["categories"])
            print(
                f"{ip_str}: {f['name']} | score={sc:.2f}"
                + (f" | flags={fl}" if fl else "")
                + (f" | cats={ca}" if ca else "")
            )


if len(sys.argv) < 2:
    print("Usage: python lookup.py <ip> [<ip> ...]")
    sys.exit(1)
_, feeds = load()
for ip in sys.argv[1:]:
    try:
        lookup(feeds, ip)
    except ValueError:
        print(f"{ip}: invalid IP")
