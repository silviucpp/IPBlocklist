"""Reader and writer for the IPBL v2 binary format read by ``mod_ip_risk`` and ``lookup.py``.

Layout: ``IPBL``, u8 version (2), u32 LE timestamp, flag table, category
table (each u8 count + u8 length-prefixed UTF-8 names), u16 feed count, then
per feed: name, u8 base score (0-200), u8 confidence (0-200), u32 LE flag
mask, u8 category mask, u32 LE range count and the ranges as varint pairs
(delta from the previous start, size). IPv4 and IPv6 ranges share one
sorted list; IPv4 is everything up to ``0xFFFFFFFF``.
"""

import hashlib
import io
import struct
from dataclasses import dataclass, field

from . import ranges as R

MAGIC = b"IPBL"
VERSION = 2
MAX_FLAGS = 32  # u32 mask
MAX_CATEGORIES = 8  # u8 mask


@dataclass
class FeedRecord:
    name: str
    v4: list = field(default_factory=list)
    v6: list = field(default_factory=list)
    base_score: float = 0.5
    confidence: float = 0.5
    categories: tuple = ()
    flags: tuple = ()


def _varint(buf, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            buf.write(bytes([byte | 0x80]))
        else:
            buf.write(bytes([byte]))
            return


def _table(records, attr):
    seen = []
    for record in records:
        for value in getattr(record, attr):
            if value not in seen:
                seen.append(value)
    return seen


def _mask(values, table):
    mask = 0
    for value in values:
        mask |= 1 << table.index(value)
    return mask


def _write_names(buf, names):
    buf.write(struct.pack("<B", len(names)))
    for name in names:
        encoded = name.encode("utf-8")
        buf.write(struct.pack("<B", len(encoded)))
        buf.write(encoded)


def dumps(timestamp, records):
    flags = _table(records, "flags")
    categories = _table(records, "categories")
    if len(flags) > MAX_FLAGS:
        raise ValueError(f"{len(flags)} distinct flags do not fit the {MAX_FLAGS}-bit mask")
    if len(categories) > MAX_CATEGORIES:
        raise ValueError(f"{len(categories)} categories do not fit the {MAX_CATEGORIES}-bit mask")

    buf = io.BytesIO()
    buf.write(MAGIC)
    buf.write(struct.pack("<BI", VERSION, timestamp))
    _write_names(buf, flags)
    _write_names(buf, categories)
    buf.write(struct.pack("<H", len(records)))
    for record in records:
        name = record.name.encode("utf-8")
        buf.write(struct.pack("<B", len(name)))
        buf.write(name)
        buf.write(struct.pack("<B", min(200, int(record.base_score * 200))))
        buf.write(struct.pack("<B", min(200, int(record.confidence * 200))))
        buf.write(struct.pack("<I", _mask(record.flags, flags)))
        buf.write(struct.pack("<B", _mask(record.categories, categories)))
        merged = record.v4 + record.v6  # every IPv4 address sorts before every IPv6 one
        buf.write(struct.pack("<I", len(merged)))
        previous = 0
        for start, end in merged:
            _varint(buf, start - previous)
            _varint(buf, end - start)
            previous = start
    return buf.getvalue()


def write(path, timestamp, records):
    with open(path, "wb") as fh:
        fh.write(dumps(timestamp, records))


def content_hash(records):
    """Hash of the published data, independent of the generation timestamp."""
    return hashlib.sha256(dumps(0, records)).hexdigest()


class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, fmt):
        values = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += struct.calcsize(fmt)
        return values if len(values) > 1 else values[0]

    def text(self):
        length = self.take("<B")
        value = self.data[self.pos : self.pos + length].decode("utf-8")
        self.pos += length
        return value

    def varint(self):
        result = shift = 0
        while True:
            byte = self.data[self.pos]
            self.pos += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7


def loads(data):
    """Parse a blocklist into ``(timestamp, {name: FeedRecord})``."""
    if data[:4] != MAGIC:
        raise ValueError("not an IPBL file")
    reader = _Reader(data)
    reader.pos = 4
    version, timestamp = reader.take("<BI")
    if version != VERSION:
        raise ValueError(f"unsupported IPBL version {version}")
    flags = [reader.text() for _ in range(reader.take("<B"))]
    categories = [reader.text() for _ in range(reader.take("<B"))]
    feeds = {}
    for _ in range(reader.take("<H")):
        name = reader.text()
        base_score, confidence = reader.take("<BB")
        flag_mask, category_mask = reader.take("<IB")
        count = reader.take("<I")
        v4, v6, start = [], [], 0
        for _ in range(count):
            start += reader.varint()
            end = start + reader.varint()
            (v4 if end <= R.MAX[R.V4] else v6).append((start, end))
        feeds[name] = FeedRecord(
            name=name,
            v4=v4,
            v6=v6,
            base_score=base_score / 200,
            confidence=confidence / 200,
            categories=tuple(c for i, c in enumerate(categories) if category_mask >> i & 1),
            flags=tuple(f for i, f in enumerate(flags) if flag_mask >> i & 1),
        )
    return timestamp, feeds


def read(path):
    with open(path, "rb") as fh:
        return loads(fh.read())
