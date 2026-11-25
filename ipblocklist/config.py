"""Load and validate ``feeds.json``.

Derived from kboykov/Threatkill (Apache-2.0), see NOTICE.
"""

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Must match what ``mod_ip_risk`` understands (plus is_isp/is_anycast/is_crawler,
# which it currently ignores). The binary format stores categories in one byte
# and flags in four, so keep these tables within 8 and 32 entries.
CATEGORIES = (
    "attacks",
    "malware",
    "botnet",
    "anonymizer",
    "spam",
    "compromised",
    "infrastructure",
)

FLAGS = (
    "is_scanner",
    "is_brute_force",
    "is_malware",
    "is_phishing",
    "is_c2_server",
    "is_tor",
    "is_vpn",
    "is_proxy",
    "is_spammer",
    "is_compromised",
    "is_datacenter",
    "is_cdn",
    "is_anycast",
    "is_isp",
    "is_mobile",
    "is_crawler",
)

_NAME = re.compile(r"^[a-z0-9_]{1,64}$")
_KNOWN_KEYS = {
    "name",
    "url",
    "description",
    "regex",
    "base_score",
    "confidence",
    "flags",
    "categories",
    "provider_name",
    "allow_http",
    "is_asn",
    "asns",
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    regex: object  # compiled pattern, or None for a feed made only of static ASNs
    categories: tuple
    description: str = ""
    base_score: float = 0.5
    confidence: float = 0.5
    flags: tuple = field(default_factory=tuple)
    provider_name: str = ""
    is_asn: bool = False
    asns: tuple = None  # static ASN list; when set the URL is not downloaded


def _check_score(name, key, value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise ConfigError(f"{name}: {key} must be a number between 0 and 1, got {value!r}")
    return float(value)


def parse_feeds(raw):
    """Validate the decoded JSON list and return ``Feed`` objects."""
    if not isinstance(raw, list) or not raw:
        raise ConfigError("feeds.json must be a non-empty list")
    feeds, seen, errors = [], set(), []
    for index, entry in enumerate(raw):
        label = entry.get("name", f"entry #{index}") if isinstance(entry, dict) else f"entry #{index}"
        try:
            if not isinstance(entry, dict):
                raise ConfigError(f"{label}: must be an object")
            unknown = set(entry) - _KNOWN_KEYS
            if unknown:
                raise ConfigError(f"{label}: unknown keys {sorted(unknown)}")
            name = entry.get("name", "")
            if not isinstance(name, str) or not _NAME.match(name):
                raise ConfigError(f"{label}: name must match {_NAME.pattern}")
            if name in seen:
                raise ConfigError(f"{name}: duplicate name")
            seen.add(name)

            asns = entry.get("asns")
            url = entry.get("url", "")
            scheme = urlparse(url).scheme
            if asns is None and scheme != "https" and not (scheme == "http" and entry.get("allow_http")):
                raise ConfigError(f"{name}: url must use https (set allow_http to override)")


            if asns is not None and (not isinstance(asns, list) or not asns):
                raise ConfigError(f"{name}: asns must be a non-empty list")
            is_asn = bool(entry.get("is_asn"))
            if asns is not None and not is_asn:
                raise ConfigError(f"{name}: asns requires is_asn")

            pattern = entry.get("regex", "")
            regex = None
            if pattern or asns is None:
                try:
                    regex = re.compile(pattern)
                except (re.error, TypeError) as exc:
                    raise ConfigError(f"{name}: regex does not compile: {exc}") from None
                if not pattern or regex.groups < 1:
                    raise ConfigError(f"{name}: regex needs at least one capture group")

            categories = entry.get("categories") or []
            bad = [c for c in categories if c not in CATEGORIES]
            if not categories or bad:
                raise ConfigError(f"{name}: categories must be a non-empty subset of {CATEGORIES}")
            flags = entry.get("flags", [])
            bad = [f for f in flags if f not in FLAGS]
            if bad:
                raise ConfigError(f"{name}: unknown flags {bad}")

            feeds.append(
                Feed(
                    name=name,
                    url=url,
                    regex=regex,
                    categories=tuple(categories),
                    description=entry.get("description", ""),
                    base_score=_check_score(name, "base_score", entry.get("base_score", 0.5)),
                    confidence=_check_score(name, "confidence", entry.get("confidence", 0.5)),
                    flags=tuple(flags),
                    provider_name=entry.get("provider_name", ""),
                    is_asn=is_asn,
                    asns=tuple(asns) if asns is not None else None,
                )
            )
        except ConfigError as exc:
            errors.append(str(exc))
    if errors:
        raise ConfigError("invalid feeds.json:\n  " + "\n  ".join(errors))
    return feeds


def load_feeds(path):
    with open(path, encoding="utf-8") as fh:
        return parse_feeds(json.load(fh))
