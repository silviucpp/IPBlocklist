"""Download feed sources.

Derived from kboykov/Threatkill (Apache-2.0), see NOTICE. TLS is always
verified. ``bgp.tools`` blocks plain clients, so it goes through curl_cffi
when that is installed.
"""

import email.utils
import random
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

try:
    from curl_cffi import requests as cffi_requests

    CFFI_AVAILABLE = True
except ImportError:  # optional dependency
    CFFI_AVAILABLE = False

USER_AGENT = "Mozilla/5.0"
CFFI_BROWSERS = ("chrome120", "chrome119", "edge99", "safari15_5")
CFFI_HOSTS = ("bgp.tools",)


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


def _get_urllib(url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="ignore")
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
    return response.text, _last_modified(response.headers.get("last-modified"))


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


def fetch_all(feeds, workers=10, downloader=download):
    """Return ``{feed.name: FetchResult}`` for every feed."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda feed: (feed.name, downloader(feed.url)), feeds)
        return dict(results)
