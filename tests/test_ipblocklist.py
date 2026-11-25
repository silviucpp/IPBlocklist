import ipaddress
import json
import os
import tempfile
import types
import unittest

from ipblocklist import asn, binfmt, pipeline
from ipblocklist import ranges as R
from ipblocklist.config import ConfigError, load_feeds, parse_feeds
from ipblocklist import fetch
from ipblocklist.fetch import FetchResult
from ipblocklist.filters import AddressFilter
from ipblocklist.parse import ParsedFeed, parse_entry, parse_feed
from ipblocklist.reconcile import MAX_STALE_RUNS, Decision, check_run, decide

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERIC = r"^(?![#;/])([0-9a-fA-F:.]+(?:/\d+)?)"


def ip(text):
    return int(ipaddress.ip_address(text))


def entry(**overrides):
    base = {
        "name": "test_feed",
        "url": "https://example.com/list.txt",
        "regex": GENERIC,
        "categories": ["attacks"],
        "flags": ["is_scanner"],
        "base_score": 0.9,
        "confidence": 0.8,
    }
    base.update(overrides)
    return base


def parsed(*cidrs):
    return parse_feed(list(cidrs), __import__("re").compile(GENERIC))


class RangeTests(unittest.TestCase):
    def test_merge(self):
        self.assertEqual(R.merge([(5, 9), (1, 3), (4, 4), (20, 30), (25, 26)]), [(1, 9), (20, 30)])

    def test_subtract_and_intersect(self):
        self.assertEqual(R.subtract([(0, 100)], [(10, 20), (50, 60)]), [(0, 9), (21, 49), (61, 100)])
        self.assertEqual(R.subtract([(10, 20)], [(0, 100)]), [])
        self.assertEqual(R.intersect([(0, 10), (20, 30)], [(5, 25)]), [(5, 10), (20, 25)])

    def test_to_cidrs(self):
        self.assertEqual(R.to_cidrs([(ip("1.2.3.0"), ip("1.2.3.255"))], R.V4), ["1.2.3.0/24"])


class ParseTests(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(parse_entry("1.2.3.4"), (4, ip("1.2.3.4"), ip("1.2.3.4")))
        self.assertEqual(parse_entry("1.2.3.0/24"), (4, ip("1.2.3.0"), ip("1.2.3.255")))
        self.assertEqual(parse_entry("::ffff:1.2.3.4"), (4, ip("1.2.3.4"), ip("1.2.3.4")))
        self.assertEqual(parse_entry("2001:db8::/32")[0], 6)

    def test_ip_range_and_integer_range(self):
        self.assertEqual(parse_entry("1.2.3.4-1.2.3.9"), (4, ip("1.2.3.4"), ip("1.2.3.9")))
        self.assertEqual(parse_entry("16909060-16909065"), (4, 16909060, 16909065))
        self.assertIsNone(parse_entry("1.2.3.9-1.2.3.4"))
        self.assertIsNone(parse_entry("1.2.3.4-::1"))

    def test_invalid(self):
        for text in ("", "abc", "1.2.3", "1.2.3.4:80", "999.1.1.1"):
            self.assertIsNone(parse_entry(text), text)

    def test_too_broad_and_invalid_counted(self):
        feed = parsed("0.0.0.0/1", "1.2.3.0/24", "abc", "# c")
        self.assertEqual(feed.too_broad, 1)
        self.assertEqual(feed.invalid, 1)  # "abc" matches the hex regex but is not an address
        self.assertEqual(feed.v4, [(ip("1.2.3.0"), ip("1.2.3.255"))])
        feed = parse_feed(["1.2.3.4-1.2.3.9", "bogus"], __import__("re").compile(r"(\S+)"))
        self.assertEqual((feed.invalid, len(feed.v4)), (1, 1))


class FilterTests(unittest.TestCase):
    def test_bogons_removed(self):
        f = AddressFilter()
        data = [(ip("9.0.0.0"), ip("11.255.255.255"))]  # spans 10.0.0.0/8
        self.assertEqual(
            f.apply(R.V4, data), [(ip("9.0.0.0"), ip("9.255.255.255")), (ip("11.0.0.0"), ip("11.255.255.255"))]
        )

    def test_ipv6_global_only(self):
        f = AddressFilter()
        self.assertEqual(f.apply(R.V6, [(ip("fe80::"), ip("fe80::ff"))]), [])
        kept = [(ip("2606:4700::"), ip("2606:4700::ffff"))]
        self.assertEqual(f.apply(R.V6, kept), kept)
        self.assertEqual(f.apply(R.V6, [(ip("2001:db8::"), ip("2001:db8::ff"))]), [])


class ConfigTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_feeds([entry()])[0].name, "test_feed")

    def test_errors(self):
        cases = [
            entry(name="Bad Name"),
            entry(url="http://example.com/x"),
            entry(regex="no group"),
            entry(regex="("),
            entry(categories=["nope"]),
            entry(flags=["is_nope"]),
            entry(base_score=1.5),
            entry(extra=1),
        ]
        for case in cases:
            with self.assertRaises(ConfigError, msg=str(case)):
                parse_feeds([case])
        with self.assertRaises(ConfigError):
            parse_feeds([entry(), entry()])

    def test_allow_http_and_static_asns(self):
        parse_feeds([entry(url="http://example.com/x", allow_http=True)])
        feed = parse_feeds([entry(is_asn=True, asns=[1, "AS2"], regex="", url="n/a")])[0]
        self.assertIsNone(feed.regex)
        with self.assertRaises(ConfigError):
            parse_feeds([entry(asns=[1])])  # asns without is_asn

    def test_repository_feeds_json_is_valid(self):
        feeds = load_feeds(os.path.join(ROOT, "feeds.json"))
        self.assertGreater(len(feeds), 100)


class FetchTests(unittest.TestCase):
    def test_plain_text(self):
        self.assertEqual(fetch.decode_body(b"1.2.3.4\n"), "1.2.3.4\n")

    def test_gzip(self):
        import gzip

        self.assertEqual(fetch.decode_body(gzip.compress(b"1.2.3.4\n5.6.7.8\n")), "1.2.3.4\n5.6.7.8\n")

    def test_zip(self):
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "1.2.3.4")
            archive.writestr("b.txt", "5.6.7.8")
        self.assertEqual(fetch.decode_body(buffer.getvalue()), "1.2.3.4\n5.6.7.8")

    def test_decompression_bomb_is_rejected(self):
        import gzip

        original = fetch.MAX_DECOMPRESSED
        fetch.MAX_DECOMPRESSED = 100
        try:
            with self.assertRaises(ValueError):
                fetch.decode_body(gzip.compress(b"x" * 1000))
        finally:
            fetch.MAX_DECOMPRESSED = original


class SecretUrlTests(unittest.TestCase):
    KEY = "s3cr3t-key"

    def test_resolve_substitutes_environment(self):
        url, secrets = fetch.resolve_url("https://x.example/{API_KEY}/a.csv", {"API_KEY": self.KEY})
        self.assertEqual(url, f"https://x.example/{self.KEY}/a.csv")
        self.assertEqual(secrets, {"API_KEY": self.KEY})

    def test_plain_url_untouched(self):
        self.assertEqual(fetch.resolve_url("https://x.example/a.txt", {}), ("https://x.example/a.txt", {}))

    def test_missing_variable_fails_that_feed_only(self):
        feeds = [
            types.SimpleNamespace(name="keyed", url="https://x.example/{API_KEY}/a.csv"),
            types.SimpleNamespace(name="plain", url="https://x.example/b.txt"),
        ]
        results = fetch.fetch_all(feeds, downloader=lambda url: FetchResult(lines=["1.1.1.1"]), environ={})
        self.assertIn("API_KEY", results["keyed"].error)
        self.assertTrue(results["plain"].ok)

    def test_secret_is_removed_from_errors(self):
        feeds = [types.SimpleNamespace(name="keyed", url="https://x.example/{API_KEY}/a.csv")]
        downloader = lambda url: FetchResult(error=f"HTTPError for {url}")
        results = fetch.fetch_all(feeds, downloader=downloader, environ={"API_KEY": self.KEY})
        self.assertNotIn(self.KEY, results["keyed"].error)
        self.assertIn("{API_KEY}", results["keyed"].error)

    def test_downloader_receives_resolved_url(self):
        seen = []
        feeds = [types.SimpleNamespace(name="keyed", url="https://x.example/{API_KEY}/a.csv")]
        fetch.fetch_all(feeds, downloader=lambda url: seen.append(url) or FetchResult(lines=[]), environ={"API_KEY": self.KEY})
        self.assertEqual(seen, [f"https://x.example/{self.KEY}/a.csv"])


class ReconcileTests(unittest.TestCase):
    def previous(self, n=100):
        return binfmt.FeedRecord("f", v4=[(i * 10, i * 10) for i in range(n)])

    def fresh(self, n):
        return ParsedFeed(v4=[(i * 10, i * 10) for i in range(n)])

    def test_ok(self):
        self.assertEqual(decide(self.fresh(90), None, self.previous(), {}).status, "ok")

    def test_failed_download_reuses_previous(self):
        d = decide(None, "timeout", self.previous(), {})
        self.assertEqual((d.status, d.stale_runs, len(d.v4)), ("stale", 1, 100))

    def test_gives_up_after_max_stale_runs(self):
        d = decide(None, "x", self.previous(), {"stale_runs": MAX_STALE_RUNS})
        self.assertEqual((d.status, d.entries), ("failed", 0))

    def test_shrink_then_accept(self):
        self.assertEqual(decide(self.fresh(10), None, self.previous(), {}).status, "stale")
        self.assertEqual(decide(self.fresh(10), None, self.previous(), {"stale_runs": 2}).status, "ok")

    def test_no_previous_and_empty_fails(self):
        self.assertEqual(decide(ParsedFeed(), None, None, {}).status, "failed")

    def test_check_run(self):
        ok = {"a": Decision([], [], "ok"), "b": Decision([], [], "ok")}
        self.assertEqual(check_run(ok, {}, {}), [])
        bad = {"a": Decision([], [], "failed"), "b": Decision([], [], "ok")}
        self.assertEqual(len(check_run(bad, {}, {})), 1)
        prev = {"categories": {"attacks": {"ranges_v4": 1000, "ranges_v6": 0}}}
        self.assertEqual(len(check_run(ok, {"attacks": {"ranges_v4": 100, "ranges_v6": 0}}, prev)), 1)
        self.assertEqual(check_run(ok, {"attacks": {"ranges_v4": 900, "ranges_v6": 0}}, prev), [])


class BinfmtTests(unittest.TestCase):
    def records(self):
        return [
            binfmt.FeedRecord(
                "one", v4=[(1, 5), (100, 200)], v6=[(ip("2606:4700::"), ip("2606:4700::ff"))],
                base_score=0.5, confidence=0.9, categories=("attacks",), flags=("is_scanner", "is_tor"),
            ),
            binfmt.FeedRecord("two", v4=[(7, 7)], base_score=1.0, confidence=1.0, categories=("spam",), flags=("is_spammer",)),
        ]

    def test_roundtrip(self):
        timestamp, feeds = binfmt.loads(binfmt.dumps(1234, self.records()))
        self.assertEqual(timestamp, 1234)
        one = feeds["one"]
        self.assertEqual(one.v4, [(1, 5), (100, 200)])
        self.assertEqual(one.v6, [(ip("2606:4700::"), ip("2606:4700::ff"))])
        self.assertEqual((one.flags, one.categories), (("is_scanner", "is_tor"), ("attacks",)))
        self.assertEqual(feeds["two"].v4, [(7, 7)])

    def test_content_hash_ignores_timestamp(self):
        self.assertEqual(binfmt.content_hash(self.records()), binfmt.content_hash(self.records()))

    def test_limits(self):
        flags = tuple(f"f{i}" for i in range(33))
        with self.assertRaises(ValueError):
            binfmt.dumps(0, [binfmt.FeedRecord("x", flags=flags)])
        cats = tuple(f"c{i}" for i in range(9))
        with self.assertRaises(ValueError):
            binfmt.dumps(0, [binfmt.FeedRecord("x", categories=cats)])

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            binfmt.loads(b"NOPE" + b"\0" * 20)


class AsnTests(unittest.TestCase):
    def test_failures_are_not_cached(self):
        calls = []

        def fetcher(number):
            calls.append(number)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return ["1.2.3.0/24"]

        resolver = asn.AsnResolver(fetcher=fetcher)
        self.assertEqual(resolver.lookup("1"), ([], False))
        self.assertNotIn("1", resolver.cache)
        self.assertEqual(resolver.lookup("1"), (["1.2.3.0/24"], True))
        self.assertEqual(resolver.lookup("1"), (["1.2.3.0/24"], True))
        self.assertEqual(len(calls), 2)

    def test_empty_success_is_cached(self):
        resolver = asn.AsnResolver(fetcher=lambda n: [])
        self.assertEqual(resolver.lookup("9"), ([], True))
        self.assertIn("9", resolver.cache)


class PipelineTests(unittest.TestCase):
    def feeds_file(self, directory):
        path = os.path.join(directory, "feeds.json")
        with open(path, "w") as fh:
            json.dump(
                [
                    entry(name="good", url="https://x/good"),
                    entry(name="flaky", url="https://x/flaky", flags=["is_spammer"], categories=["spam"]),
                    entry(name="asnfeed", url="n/a", is_asn=True, asns=[64500], regex="", flags=["is_vpn"], categories=["anonymizer"]),
                ],
                fh,
            )
        return path

    def downloader(self, flaky_ok):
        def fetch(url):
            if url.endswith("good"):
                return FetchResult(lines=["# c", "8.8.8.0/24", "10.0.0.0/8", "1.1.1.1"])
            return FetchResult(lines=["9.9.9.0/24"]) if flaky_ok else FetchResult(error="HTTP 500")

        return fetch

    def run_once(self, directory, previous, flaky_ok):
        feeds = load_feeds(self.feeds_file(directory))
        resolver = asn.AsnResolver(fetcher=lambda n: ["203.0.114.0/24", "2606:4700::/32"])
        data = pipeline.collect(feeds, resolver, downloader=self.downloader(flaky_ok))
        prev_feeds, prev_manifest = pipeline.load_previous(previous)
        records, report, stats, problems = pipeline.build(feeds, data, prev_feeds, prev_manifest, AddressFilter(), 1_000_000)
        out = os.path.join(directory, "out")
        manifest = pipeline.write_outputs(out, 1_000_000, records, report, stats, {"asnfeed": data["asnfeed"].asns}, skip_txt=True)
        return out, report, manifest, problems

    def test_fallback_to_previous_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "a"))
            out1, report1, manifest1, _ = self.run_once(os.path.join(tmp, "a"), None, True)
            self.assertEqual(report1["good"]["ranges_v4"], 2)  # 10.0.0.0/8 was filtered
            self.assertEqual(report1["flaky"]["status"], "ok")
            self.assertEqual(report1["asnfeed"]["ranges_v6"], 1)
            os.makedirs(os.path.join(tmp, "b"))
            _, report2, manifest2, problems = self.run_once(os.path.join(tmp, "b"), out1, False)
            self.assertEqual(report2["flaky"]["status"], "stale")
            self.assertEqual(report2["flaky"]["ranges_v4"], 1)
            self.assertEqual(manifest2["summary"]["stale"], 1)
            self.assertEqual(problems, [])
            self.assertEqual(manifest1["content_hash"], manifest2["content_hash"])
            for name in ("blocklist.bin", "asns.json", "manifest.json"):
                self.assertTrue(os.path.exists(os.path.join(tmp, "b", "out", name)))


if __name__ == "__main__":
    unittest.main()
