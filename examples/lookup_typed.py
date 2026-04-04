import struct
import socket
import sys
from bisect import bisect_right
from typing import NamedTuple


class Feed(NamedTuple):
    name: str
    base_score: float
    confidence: float
    flags: list[str]
    categories: list[str]
    ipv4_starts: tuple[int, ...]
    ipv4_ends: tuple[int, ...]
    ipv6_starts: tuple[int, ...]
    ipv6_ends: tuple[int, ...]


class Blocklist(NamedTuple):
    timestamp: int
    feeds: list[Feed]


def load(path: str = "blocklist.bin") -> Blocklist:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != b"IPBL":
            raise ValueError(f"invalid magic: {magic!r}")

        version = struct.unpack("<B", f.read(1))[0]
        if version != 2:
            raise ValueError(f"unsupported version: {version}")

        timestamp = struct.unpack("<I", f.read(4))[0]

        def read_varint() -> int:
            result = shift = 0
            while True:
                byte = f.read(1)[0]
                result |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    return result
                shift += 7

        def read_string() -> str:
            length = f.read(1)[0]
            return f.read(length).decode("utf-8")

        flag_count = f.read(1)[0]
        flag_table = [read_string() for _ in range(flag_count)]

        cat_count = f.read(1)[0]
        cat_table = [read_string() for _ in range(cat_count)]

        feed_count = struct.unpack("<H", f.read(2))[0]
        feeds: list[Feed] = []

        for _ in range(feed_count):
            name = read_string()
            base_score = f.read(1)[0] / 200.0
            confidence = f.read(1)[0] / 200.0
            flags_mask = struct.unpack("<I", f.read(4))[0]
            categories_mask = f.read(1)[0]

            flags = [
                flag_table[i] for i in range(len(flag_table)) if flags_mask & (1 << i)
            ]
            categories = [
                cat_table[i]
                for i in range(len(cat_table))
                if categories_mask & (1 << i)
            ]

            range_count = struct.unpack("<I", f.read(4))[0]
            v4_starts: list[int] = []
            v4_ends: list[int] = []
            v6_starts: list[int] = []
            v6_ends: list[int] = []
            current = 0

            for _ in range(range_count):
                current += read_varint()
                size = read_varint()
                end = current + size
                if end <= 0xFFFFFFFF:
                    v4_starts.append(current)
                    v4_ends.append(end)
                else:
                    v6_starts.append(current)
                    v6_ends.append(end)

            feeds.append(
                Feed(
                    name=name,
                    base_score=base_score,
                    confidence=confidence,
                    flags=flags,
                    categories=categories,
                    ipv4_starts=tuple(v4_starts),
                    ipv4_ends=tuple(v4_ends),
                    ipv6_starts=tuple(v6_starts),
                    ipv6_ends=tuple(v6_ends),
                )
            )

    return Blocklist(timestamp=timestamp, feeds=feeds)


def lookup(blocklist: Blocklist, ip_str: str) -> list[Feed]:
    try:
        packed = socket.inet_pton(socket.AF_INET, ip_str)
        target = int.from_bytes(packed, "big")
        is_v4 = True
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, ip_str)
        target = int.from_bytes(packed, "big")
        is_v4 = False

    matches: list[Feed] = []
    for feed in blocklist.feeds:
        starts = feed.ipv4_starts if is_v4 else feed.ipv6_starts
        ends = feed.ipv4_ends if is_v4 else feed.ipv6_ends
        idx = bisect_right(starts, target) - 1
        if idx >= 0 and target <= ends[idx]:
            matches.append(feed)

    return matches


def format_match(feed: Feed) -> str:
    score = feed.base_score * feed.confidence
    parts = [feed.name, f"score={score:.2f}"]
    if feed.flags:
        parts.append(f"flags={','.join(feed.flags)}")
    if feed.categories:
        parts.append(f"cats={','.join(feed.categories)}")
    return " | ".join(parts)


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python lookup_typed.py <ip> [<ip> ...]")
        return 1

    blocklist = load()

    for ip in sys.argv[1:]:
        try:
            matches = lookup(blocklist, ip)
        except (OSError, ValueError):
            print(f"{ip}: invalid IP")
            continue

        if matches:
            for feed in matches:
                print(f"{ip}: {format_match(feed)}")
        else:
            print(f"{ip}: no matches")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
