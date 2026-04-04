import ipaddress
import struct
import sys
from bisect import bisect_right
from time import perf_counter


MAGIC = b"IPBL"
IPV4_MAX = 0xFFFFFFFF


def read_varint(file_handle):
    result = 0
    shift = 0
    while True:
        byte = file_handle.read(1)
        if not byte:
            raise EOFError("unexpected end of file")

        value = byte[0]
        result |= (value & 0x7F) << shift
        if not (value & 0x80):
            return result
        shift += 7


def build_family_index(feed_index, ranges):
    ipv4_starts = []
    ipv4_ends = []
    ipv6_starts = []
    ipv6_ends = []

    for start, end in ranges:
        if end <= IPV4_MAX:
            ipv4_starts.append(start)
            ipv4_ends.append(end)
        else:
            ipv6_starts.append(start)
            ipv6_ends.append(end)

    indexed = []
    if ipv4_starts:
        indexed.append(
            (4, feed_index, tuple(ipv4_starts), tuple(ipv4_ends))
        )
    if ipv6_starts:
        indexed.append(
            (6, feed_index, tuple(ipv6_starts), tuple(ipv6_ends))
        )
    return indexed


def load_blocklist(path="blocklist.bin"):
    ipv4_feeds = []
    ipv6_feeds = []
    feeds_meta = []

    with open(path, "rb", buffering=1024 * 1024) as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError(
                f"invalid magic: {magic!r}, expected {MAGIC!r}"
            )

        version = struct.unpack("<B", f.read(1))[0]
        if version != 2:
            raise ValueError(f"unsupported version: {version}")

        timestamp = struct.unpack("<I", f.read(4))[0]

        flag_count = struct.unpack("<B", f.read(1))[0]
        flag_table = []
        for _ in range(flag_count):
            length = struct.unpack("<B", f.read(1))[0]
            flag_table.append(f.read(length).decode("utf-8"))

        cat_count = struct.unpack("<B", f.read(1))[0]
        cat_table = []
        for _ in range(cat_count):
            length = struct.unpack("<B", f.read(1))[0]
            cat_table.append(f.read(length).decode("utf-8"))

        feed_count = struct.unpack("<H", f.read(2))[0]

        for _ in range(feed_count):
            name_length = struct.unpack("<B", f.read(1))[0]
            feed_name = f.read(name_length).decode("utf-8")

            base_score = struct.unpack("<B", f.read(1))[0] / 200.0
            confidence = struct.unpack("<B", f.read(1))[0] / 200.0

            flags_mask = struct.unpack("<I", f.read(4))[0]
            cats_mask = struct.unpack("<B", f.read(1))[0]

            flags = [
                flag_table[i]
                for i in range(len(flag_table))
                if flags_mask & (1 << i)
            ]
            categories = [
                cat_table[i]
                for i in range(len(cat_table))
                if cats_mask & (1 << i)
            ]

            feed_index = len(feeds_meta)
            feeds_meta.append({
                "name": feed_name,
                "base_score": base_score,
                "confidence": confidence,
                "flags": flags,
                "categories": categories,
            })

            range_count = struct.unpack("<I", f.read(4))[0]
            ranges = []
            current_start = 0
            for _ in range(range_count):
                current_start += read_varint(f)
                range_size = read_varint(f)
                ranges.append(
                    (current_start, current_start + range_size)
                )

            for family, idx, starts, ends in build_family_index(
                feed_index, ranges
            ):
                if family == 4:
                    ipv4_feeds.append((idx, starts, ends))
                else:
                    ipv6_feeds.append((idx, starts, ends))

    return (
        timestamp,
        tuple(feeds_meta),
        tuple(ipv4_feeds),
        tuple(ipv6_feeds),
    )


def range_contains(starts, ends, target):
    index = bisect_right(starts, target) - 1
    return index >= 0 and target <= ends[index]


def lookup_ip(feeds_meta, ipv4_feeds, ipv6_feeds, ip_value):
    address = ipaddress.ip_address(ip_value)
    target = int(address)
    family_feeds = (
        ipv4_feeds if address.version == 4 else ipv6_feeds
    )

    matches = []
    for feed_index, starts, ends in family_feeds:
        if range_contains(starts, ends, target):
            matches.append(feeds_meta[feed_index])

    return matches


def format_match(meta):
    score = meta["base_score"] * meta["confidence"]
    parts = [meta["name"], f"score={score:.2f}"]
    if meta["flags"]:
        parts.append(f"flags={','.join(meta['flags'])}")
    if meta["categories"]:
        parts.append(f"cats={','.join(meta['categories'])}")
    return " | ".join(parts)


def main(argv):
    if len(argv) < 2:
        print("Usage: python lookup.py <ip> [<ip> ...]")
        return 1

    load_started = perf_counter()
    _, feeds_meta, ipv4_feeds, ipv6_feeds = load_blocklist()
    load_elapsed = perf_counter() - load_started

    lookup_started = perf_counter()
    for ip_value in argv[1:]:
        try:
            matches = lookup_ip(
                feeds_meta, ipv4_feeds, ipv6_feeds, ip_value
            )
        except ValueError:
            print(f"{ip_value}: invalid IP")
            continue

        if matches:
            for meta in matches:
                print(f"{ip_value}: {format_match(meta)}")
        else:
            print(f"{ip_value}: no matches")
    lookup_elapsed = perf_counter() - lookup_started

    print(f"load time: {load_elapsed * 1000:.2f} ms")
    print(
        f"lookup time for {len(argv) - 1} IPs:"
        f" {lookup_elapsed * 1000:.2f} ms"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))