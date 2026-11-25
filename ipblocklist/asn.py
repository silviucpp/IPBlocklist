"""ASN feeds: turn AS numbers into announced prefixes via RIPEstat.

Lookups that fail are never cached, so a transient RIPEstat error cannot
turn an ASN into an empty list that later runs trust forever.
"""

import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from .parse import extract

RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"


def normalize_asn(asn):
    value = str(asn).upper().removeprefix("AS").strip()
    return value if value.isdigit() else None


def fetch_prefixes(asn, attempts=3, timeout=20):
    """Return the announced prefixes of ``asn``; raise on any failure."""
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                RIPE_URL.format(asn=asn), headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            if data.get("status") != "ok":
                raise RuntimeError(f"RIPEstat status {data.get('status')!r}")
            return [p["prefix"] for p in data.get("data", {}).get("prefixes", []) if "prefix" in p]
        except Exception as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(attempt)
    raise last_error


class AsnResolver:
    """ASN -> prefixes with a persistent cache (``asn_prefixes.json`` layout)."""

    def __init__(self, cache=None, fetcher=fetch_prefixes):
        self.cache = dict(cache or {})
        self.fetcher = fetcher
        self._lock = threading.Lock()

    def lookup(self, asn):
        """Return ``(prefixes, ok)``. Only successful lookups are cached."""
        with self._lock:
            if asn in self.cache:
                return self.cache[asn], True
        try:
            prefixes = self.fetcher(asn)
        except Exception as exc:
            print(f"Failed to retrieve AS{asn}: {exc}")
            return [], False
        with self._lock:
            self.cache[asn] = prefixes
        return prefixes, True


def asn_list(feed, fetch_result):
    """Sorted unique AS numbers of an ASN feed (static list or extracted)."""
    if feed.asns is not None:
        raw = feed.asns
    else:
        raw = [text for line in fetch_result.lines for text in extract(line, feed.regex)]
    return sorted({n for n in map(normalize_asn, raw) if n is not None}, key=int)


def resolve_feed(feed, fetch_result, resolver, workers=10):
    """Return ``(asns, prefixes, failures)`` for one ASN feed."""
    asns = asn_list(feed, fetch_result)
    prefixes, failures = [], 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(resolver.lookup, asn): asn for asn in asns}
        for future in as_completed(futures):
            found, ok = future.result()
            prefixes.extend(found)
            failures += not ok
    return asns, prefixes, failures
