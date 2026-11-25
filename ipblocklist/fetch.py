"""Download feed sources.

Derived from kboykov/Threatkill (Apache-2.0), see NOTICE. TLS is always
verified. ``bgp.tools`` blocks plain clients, so it goes through curl_cffi
when that is installed.
"""

import email.utils
import gzip
import io
import os
import random
import re
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

try:
    from curl_cffi import requests as cffi_requests

    CFFI_AVAILABLE = True
except ImportError:  # optional dependency
    CFFI_AVAILABLE = False

USER_AGENT = "Mozilla/5.0"
MAX_DECOMPRESSED = 256 * 1024 * 1024  # guards against decompression bombs
CFFI_BROWSERS = ("chrome120", "chrome119", "edge99", "safari15_5")
CFFI_HOSTS = ("bgp.tools",)


PLACEHOLDER = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")


class MissingSecret(Exception):
    """A feed URL refers to an environment variable that is not set."""


def resolve_url(url, environ=None):
    """Replace ``{NAME}`` placeholders with environment variables.

    Returns ``(url, secrets)`` where ``secrets`` maps each substituted
    variable name to its value, so callers can scrub it from messages.
    """
    environ = os.environ if environ is None else environ
    secrets = {}

    def substitute(match):
        name = match.group(1)
        value = environ.get(name)
        if not value:
            raise MissingSecret(name)
        secrets[name] = value
        return value

    return PLACEHOLDER.sub(substitute, url), secrets


def redact(text, secrets):
    """Hide secret values in ``text``, showing the variable name instead."""
    for name, value in secrets.items():
        text = text.replace(value, "{" + name + "}")
    return text


@dataclass
class FetchResult:
    lines: list = None
    error: str = None
    last_modified: float = None  # Unix time from the Last-Modified header, if any

    @property
    def ok(self):
        return self.error is None


def _last_modified(value):
    if not value:
        return None
    try:
        return email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return None


def _bounded(stream):
    data = stream.read(MAX_DECOMPRESSED + 1)
    if len(data) > MAX_DECOMPRESSED:
        raise ValueError(f"decompressed data exceeds {MAX_DECOMPRESSED} bytes")
    return data


def decode_body(raw):
    """Return the text of a download, unpacking gzip files and zip archives."""
    if raw[:2] == b"\x1f\x8b":
        raw = _bounded(gzip.GzipFile(fileobj=io.BytesIO(raw)))
    elif raw[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            parts = []
            for info in archive.infolist():
                if not info.is_dir():
                    with archive.open(info) as member:
                        parts.append(_bounded(member))
            raw = b"\n".join(parts)
    return raw.decode("utf-8", errors="ignore")


def _get_urllib(url, timeout):
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = decode_body(response.read())
        return body, _last_modified(response.headers.get("Last-Modified"))


def _get_cffi(url, timeout):
    response = cffi_requests.get(
        url,
        impersonate=random.choice(CFFI_BROWSERS),
        headers={"Accept-Language": "en-US,en;q=0.9"},
        timeout=timeout,
    )
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code}")
    return decode_body(response.content), _last_modified(response.headers.get("last-modified"))


def download(url, timeout=60, attempts=3, backoff=2.0):
    """Fetch ``url``; HTTP errors (4xx/5xx) and network errors are retried."""
    use_cffi = CFFI_AVAILABLE and any(host in url for host in CFFI_HOSTS)
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            body, stamp = (_get_cffi if use_cffi else _get_urllib)(url, timeout)
            return FetchResult(lines=body.splitlines(), last_modified=stamp)
        except Exception as exc:  # network, TLS, HTTP and decode errors all count
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < attempts:
                time.sleep(backoff**attempt)
    return FetchResult(error=last_error)


def _fetch_feed(feed, downloader, environ):
    try:
        url, secrets = resolve_url(feed.url, environ)
    except MissingSecret as exc:
        return FetchResult(error=f"environment variable {exc.args[0]} is not set")
    result = downloader(url)
    if secrets and result.error:
        result = FetchResult(error=redact(result.error, secrets), last_modified=result.last_modified)
    return result


def fetch_all(feeds, workers=10, downloader=download, environ=None):
    """Return ``{feed.name: FetchResult}`` for every feed.

    URLs may contain ``{NAME}`` placeholders, filled from the environment; the
    resolved URL (which holds the secret) is never stored or reported.
    """
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda feed: (feed.name, _fetch_feed(feed, downloader, environ)), feeds)
        return dict(results)
