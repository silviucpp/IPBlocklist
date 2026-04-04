import ipaddress
import struct
import sys
from bisect import bisect_right
from time import perf_counter


FEED_COUNT_STRUCT = struct.Struct("<H")
NAME_LENGTH_STRUCT = struct.Struct("<B")
RANGE_COUNT_STRUCT = struct.Struct("<I")
TIMESTAMP_STRUCT = struct.Struct("<I")
IPV4_MAX = 0xFFFFFFFF


def read_varint(file_handle):
    result = 0
    shift = 0
    while True:
        byte = file_handle.read(1)
        if not byte:
            raise EOFError("unexpected end of file while reading varint")

        value = byte[0]
        result |= (value & 0x7F) << shift
        if not (value & 0x80):
            return result
        shift += 7


def build_family_index(feed_name, ranges):
    ipv4_starts = []
    ipv4_ends = []
    ipv6_starts = []
    ipv6_ends = []

    for start, end in ranges:
        if end <= IPV4_MAX:
            ipv4_starts.append(start)
            ipv4_ends.append(end)
            continue

        ipv6_starts.append(start)
        ipv6_ends.append(end)

    indexed = []
    if ipv4_starts:
        indexed.append((4, feed_name, tuple(ipv4_starts), tuple(ipv4_ends)))
    if ipv6_starts:
        indexed.append((6, feed_name, tuple(ipv6_starts), tuple(ipv6_ends)))
    return indexed


def load_blocklist(path="blocklist.bin"):
    ipv4_feeds = []
    ipv6_feeds = []

    with open(path, "rb", buffering=1024 * 1024) as file_handle:
        timestamp = TIMESTAMP_STRUCT.unpack(file_handle.read(4))[0]
        feed_count = FEED_COUNT_STRUCT.unpack(file_handle.read(2))[0]

        for _ in range(feed_count):
            name_length = NAME_LENGTH_STRUCT.unpack(file_handle.read(1))[0]
            feed_name = file_handle.read(name_length).decode("utf-8")
            range_count = RANGE_COUNT_STRUCT.unpack(file_handle.read(4))[0]

            ranges = []
            current_start = 0
            for _ in range(range_count):
                current_start += read_varint(file_handle)
                range_size = read_varint(file_handle)
                ranges.append((current_start, current_start + range_size))

            for family, name, starts, ends in build_family_index(feed_name, ranges):
                if family == 4:
                    ipv4_feeds.append((name, starts, ends))
                else:
                    ipv6_feeds.append((name, starts, ends))

    return timestamp, tuple(ipv4_feeds), tuple(ipv6_feeds)


def range_contains(starts, ends, target):
    index = bisect_right(starts, target) - 1
    return index >= 0 and target <= ends[index]


def lookup_ip(ipv4_feeds, ipv6_feeds, ip_value):
    address = ipaddress.ip_address(ip_value)
    target = int(address)
    family_feeds = ipv4_feeds if address.version == 4 else ipv6_feeds
    matches = []

    for feed_name, starts, ends in family_feeds:
        if range_contains(starts, ends, target):
            matches.append(feed_name)

    return matches


def main(argv):
    if len(argv) < 2:
        print("Usage: python lookup.py <ip> <ip> ...")
        return 1

    load_started = perf_counter()
    _, ipv4_feeds, ipv6_feeds = load_blocklist()
    load_elapsed = perf_counter() - load_started

    lookup_started = perf_counter()
    for ip_value in argv[1:]:
        try:
            matches = lookup_ip(ipv4_feeds, ipv6_feeds, ip_value)
        except ValueError:
            print(f"{ip_value}: invalid IP")
            continue

        if matches:
            print(f"{ip_value}: {', '.join(matches)}")
        else:
            print(f"{ip_value}: no matches")
    lookup_elapsed = perf_counter() - lookup_started

    print(f"load time: {load_elapsed * 1000:.2f} ms")
    print(
        f"lookup time for {len(argv) - 1} IPs: {lookup_elapsed * 1000:.2f} ms"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))