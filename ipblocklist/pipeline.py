"""End-to-end run: fetch -> parse -> reconcile -> filter -> validate -> write.

Structure derived from kboykov/Threatkill (Apache-2.0), see NOTICE.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass

from . import asn, binfmt
from . import ranges as R
from .config import CATEGORIES, ConfigError, load_feeds
from .fetch import FetchResult, download, fetch_all
from .filters import AddressFilter
from .parse import ParsedFeed, parse_entries, parse_feed
from .reconcile import UPSTREAM_STALE_DAYS, category_stats, check_run, decide

MANIFEST_VERSION = 1
ASN_PREFIXES = "asn_prefixes.json"
OUTPUT_FILES = ("blocklist.bin", "blocklist.txt", "asns.json", ASN_PREFIXES)

# blocklist.txt keeps ranges whose combined score reaches this threshold
TXT_THRESHOLD = 0.5
TXT_COVERAGE_PCT = 90

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class FeedData:
    """What one feed produced this run, before reconciling with the last run."""

    parsed: ParsedFeed = None  # None when the feed could not be read at all
    error: str = None
    last_modified: float = None
    asns: list = None
    asn_failures: int = 0


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def write_json(path, data):
    temp = f"{path}.tmp"
    with open(temp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(temp, path)


def load_previous(directory):
    """Return ``(feeds_by_name, manifest)`` from a previous release, if present."""
    feeds, manifest = {}, {}
    if not directory:
        return feeds, manifest
    bin_path = os.path.join(directory, "blocklist.bin")
    if os.path.exists(bin_path):
        try:
            _, feeds = binfmt.read(bin_path)
        except (ValueError, IndexError, OSError, struct.error) as exc:  # corrupt or truncated
            print(f"warning: ignoring unreadable {bin_path}: {exc}")
    manifest_path = os.path.join(directory, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            manifest = read_json(manifest_path, {})
        except ValueError as exc:
            print(f"warning: ignoring unreadable {manifest_path}: {exc}")
    return feeds, manifest


def collect(feeds, resolver, workers=10, downloader=download):
    """Download and parse every feed. Returns ``{feed.name: FeedData}``."""
    to_download = [f for f in feeds if f.asns is None]
    fetched = fetch_all(to_download, workers=workers, downloader=downloader)
    data = {}
    for feed in feeds:
        result = fetched.get(feed.name) or FetchResult(lines=[])
        if not feed.is_asn:
            parsed = parse_feed(result.lines, feed.regex) if result.ok else None
            data[feed.name] = FeedData(parsed, result.error, result.last_modified)
        elif feed.asns is None and not result.ok:
            data[feed.name] = FeedData(None, result.error, result.last_modified)
        else:
            print(f"Resolving ASN ranges for {feed.name}...")
            asns, prefixes, failures = asn.resolve_feed(feed, result, resolver, workers)
            data[feed.name] = FeedData(
                parse_entries(prefixes), None, result.last_modified, asns, failures
            )
    return data


def build(feeds, data, previous_feeds, previous_manifest, address_filter, now):
    """Pure processing step; returns everything the writers need."""
    previous_state = previous_manifest.get("feeds", {})
    decisions, records, feed_report = {}, [], {}

    for feed in feeds:
        item = data[feed.name]
        parsed = item.parsed
        if parsed is not None:
            parsed.v4 = address_filter.apply(R.V4, parsed.v4)
            parsed.v6 = address_filter.apply(R.V6, parsed.v6)
        previous = previous_feeds.get(feed.name)
        if previous is not None:  # previous data predates the current filters
            previous.v4 = address_filter.apply(R.V4, R.merge(previous.v4))
            previous.v6 = address_filter.apply(R.V6, R.merge(previous.v6))
        error = item.error
        if parsed is not None and parsed.entries == 0 and item.asn_failures:
            error = f"{item.asn_failures} ASN lookups failed"
        decision = decide(parsed, error, previous, previous_state.get(feed.name, {}))
        decisions[feed.name] = decision

        records.append(
            binfmt.FeedRecord(
                name=feed.name,
                v4=decision.v4,
                v6=decision.v6,
                base_score=feed.base_score,
                confidence=feed.confidence,
                categories=feed.categories,
                flags=feed.flags,
            )
        )
        report = {
            "status": decision.status,
            "ranges_v4": len(decision.v4),
            "ranges_v6": len(decision.v6),
            "addresses_v4": R.address_count(decision.v4),
            "stale_runs": decision.stale_runs,
        }
        if decision.reason:
            report["reason"] = decision.reason
        if parsed is not None:
            report["invalid"] = parsed.invalid
            report["too_broad"] = parsed.too_broad
        if item.asn_failures:
            report["asn_failures"] = item.asn_failures
        if item.last_modified:
            age = (now - item.last_modified) / 86400
            report["upstream_modified"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(item.last_modified)
            )
            if age > UPSTREAM_STALE_DAYS:
                report["upstream_stale_days"] = int(age)
        feed_report[feed.name] = report

    stats = {}
    for category in CATEGORIES:
        members = [r for r in records if category in r.categories]
        if members:
            v4 = R.merge([rng for r in members for rng in r.v4])
            v6 = R.merge([rng for r in members for rng in r.v6])
            stats[category] = category_stats(v4, v6)

    problems = check_run(decisions, stats, previous_manifest)
    return records, feed_report, stats, problems


def write_scored_list(records, out_dir):
    """Write ``blocklist.txt`` (scored, CIDR-minimized) using ``cidr_minimizer``."""
    scored = [(r, r.base_score * r.confidence) for r in records]
    ipv4 = [(s, e, score) for r, score in scored for s, e in r.v4]
    ipv6 = [(s, e, score) for r, score in scored for s, e in r.v6]

    buf = bytearray()
    buf.extend(struct.pack("<f", TXT_THRESHOLD))
    buf.extend(struct.pack("<B", TXT_COVERAGE_PCT))
    buf.extend(struct.pack("<I", len(ipv4)))
    for start, end, score in ipv4:
        buf.extend(struct.pack("<IIf", start, end, score))
    buf.extend(struct.pack("<I", len(ipv6)))
    for start, end, score in ipv6:
        buf.extend(
            struct.pack("<16s16sf", start.to_bytes(16, "little"), end.to_bytes(16, "little"), score)
        )

    binary = os.path.join(ROOT, "cidr_minimizer", "target", "release", "cidr_minimizer")
    if not os.path.exists(binary):
        print("Building cidr_minimizer...")
        subprocess.run(
            ["cargo", "build", "--release"], cwd=os.path.join(ROOT, "cidr_minimizer"), check=True
        )
    print(f"Running cidr_minimizer with {len(ipv4)} IPv4 + {len(ipv6)} IPv6 scored ranges...")
    result = subprocess.run([binary], input=bytes(buf), capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"cidr_minimizer failed: {result.stderr.decode()}")
    lines = [line for line in result.stdout.decode().splitlines() if line.strip()]
    with open(os.path.join(out_dir, "blocklist.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Saved blocklist.txt with {len(lines)} entries")


def write_outputs(out_dir, timestamp, records, feed_report, stats, asn_lists, skip_txt=False):
    os.makedirs(out_dir, exist_ok=True)
    binfmt.write(os.path.join(out_dir, "blocklist.bin"), timestamp, records)
    print(f"Saved blocklist.bin with {len(records)} feeds")
    write_json(os.path.join(out_dir, "asns.json"), asn_lists)
    print(f"Saved asns.json with {len(asn_lists)} ASN feeds")
    if not skip_txt:
        write_scored_list(records, out_dir)

    files = {}
    for filename in OUTPUT_FILES:
        path = os.path.join(out_dir, filename)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                payload = fh.read()
            files[filename] = {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "binary_format_version": binfmt.VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
        "timestamp": timestamp,
        "content_hash": binfmt.content_hash(records),
        "summary": {
            "feeds": len(feed_report),
            "ok": sum(r["status"] == "ok" for r in feed_report.values()),
            "stale": sum(r["status"] == "stale" for r in feed_report.values()),
            "failed": sum(r["status"] == "failed" for r in feed_report.values()),
        },
        "categories": stats,
        "feeds": feed_report,
        "files": files,
    }
    write_json(os.path.join(out_dir, "manifest.json"), manifest)
    return manifest


def run(args):
    try:
        feeds = load_feeds(args.feeds)
    except (ConfigError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    cache_path = os.path.join(args.out, ASN_PREFIXES)
    resolver = asn.AsnResolver(read_json(cache_path, {}))
    previous_feeds, previous_manifest = load_previous(args.previous)

    print(f"Downloading {len(feeds)} feeds...")
    data = collect(feeds, resolver, workers=args.workers)
    write_json(cache_path, resolver.cache)  # a cache: keep it even if the run is refused
    print(f"Saved {ASN_PREFIXES} with {len(resolver.cache)} entries")

    now = time.time()
    records, feed_report, stats, problems = build(
        feeds, data, previous_feeds, previous_manifest, AddressFilter(), now
    )

    for name, report in feed_report.items():
        line = f"  {report['status']:6} {name}: {report['ranges_v4']} v4 / {report['ranges_v6']} v6 ranges"
        if "reason" in report:
            line += f" ({report['reason']})"
        if "upstream_stale_days" in report:
            line += f" [upstream not modified for {report['upstream_stale_days']} days]"
        print(line)
    for name, s in stats.items():
        print(f"  category {name}: {s['ranges_v4']} v4 + {s['ranges_v6']} v6 ranges")

    if problems and not args.force:
        print("Refusing to publish:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("Re-run with --force to publish anyway.", file=sys.stderr)
        return 2

    asn_lists = {f.name: data[f.name].asns for f in feeds if f.is_asn and data[f.name].asns is not None}
    try:
        manifest = write_outputs(
            args.out, int(now), records, feed_report, stats, asn_lists, skip_txt=args.skip_txt
        )
    except (RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    s = manifest["summary"]
    print(f"Wrote {args.out}/ - {s['ok']} ok, {s['stale']} stale, {s['failed']} failed feeds")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Aggregate IP intelligence feeds into blocklist.bin.")
    parser.add_argument("--feeds", default="feeds.json")
    parser.add_argument("--previous", help="directory holding the last release's blocklist.bin and manifest.json")
    parser.add_argument("--out", default=".")
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--force", action="store_true", help="publish even if validation fails")
    parser.add_argument("--skip-txt", action="store_true", help="do not build blocklist.txt (no Rust needed)")
    return run(parser.parse_args(argv))
