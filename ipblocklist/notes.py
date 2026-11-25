"""Render release notes from ``manifest.json``.

Derived from kboykov/Threatkill (Apache-2.0), see NOTICE.

Usage: python -m ipblocklist.notes manifest.json [owner/repo] > release-notes.md
"""

import json
import sys

DESCRIPTIONS = {
    "attacks": "Scanners, brute-force, web attackers",
    "malware": "Malware C2, exploit hosts, phishing",
    "botnet": "Botnet command & control nodes",
    "anonymizer": "Tor nodes, VPN servers, open proxies",
    "spam": "Spam networks and forum abusers",
    "compromised": "Compromised and hijacked hosts",
    "infrastructure": "Datacenters, CDNs, cloud providers, crawlers",
}


def render(manifest, repo):
    s = manifest["summary"]
    lines = [
        "## Automated IP intelligence update",
        "",
        f"**Generated:** {manifest['generated']}  ",
        f"**Feeds:** {s['feeds']} ({s['ok']} fresh, {s['stale']} reusing previous data, {s['failed']} failed)",
        "",
        "| Category | IPv4 ranges | IPv6 ranges | IPv4 addresses | Description |",
        "|---|---:|---:|---:|---|",
    ]
    for name, c in manifest["categories"].items():
        lines.append(
            f"| `{name}` | {c['ranges_v4']:,} | {c['ranges_v6']:,} | {c['addresses_v4']:,} | {DESCRIPTIONS.get(name, '')} |"
        )

    attention = [
        (name, f)
        for name, f in sorted(manifest["feeds"].items())
        if f["status"] != "ok" or "upstream_stale_days" in f
    ]
    if attention:
        lines += ["", "### Feeds needing attention", "", "| Feed | Status | Detail |", "|---|---|---|"]
        for name, f in attention:
            detail = f.get("reason", "")
            if "upstream_stale_days" in f:
                detail = (detail + "; " if detail else "") + f"upstream unchanged for {f['upstream_stale_days']} days"
            lines.append(f"| `{name}` | {f['status']} | {detail} |")

    lines += [
        "",
        "**Files:** `blocklist.bin` (binary, IPBL v2), `blocklist.txt` (scored, CIDR-minimized), "
        "`asns.json`, `asn_prefixes.json` and `manifest.json` (per-feed status and SHA-256 of every file).",
        "",
        "```bash",
        f"wget https://github.com/{repo}/releases/latest/download/blocklist.bin",
        "```",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__, file=sys.stderr)
        return 1
    with open(argv[0], encoding="utf-8") as fh:
        manifest = json.load(fh)
    repo = argv[1] if len(argv) > 1 else "silviucpp/IPBlocklist"
    sys.stdout.write(render(manifest, repo))
    return 0


if __name__ == "__main__":
    sys.exit(main())
