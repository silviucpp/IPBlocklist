<div align="center">

# 🔒 IPBlocklist

Threat intelligence aggregator that collects, processes, and serves IP reputation data from 128 security feeds into an optimized binary format for fast lookups and a scored, CIDR-minimized text blocklist for direct use with firewalls.

<p align="center">
<img src="https://img.shields.io/github/actions/workflow/status/tn3w/IPBlocklist/aggregate-feeds.yml?label=Build&style=for-the-badge" alt="GitHub Workflow Status">
<img src="https://img.shields.io/badge/dataset-5.0M_entries-blue?style=for-the-badge" alt="Dataset Size">
<img src="https://img.shields.io/badge/IPs-4.4M-green?style=for-the-badge" alt="Individual IPs">
<img src="https://img.shields.io/badge/ranges-552K-orange?style=for-the-badge" alt="CIDR Ranges">
</p>

<p align="center">
<a href="https://github.com/tn3w/IPBlocklist/releases/latest/download/blocklist.bin"><img src="https://img.shields.io/badge/download-blocklist.bin_(12MB)-red?style=for-the-badge&logo=download&logoColor=white" alt="Download Threat Data"></a>
<a href="https://github.com/tn3w/IPBlocklist/releases/latest/download/blocklist.txt"><img src="https://img.shields.io/badge/download-blocklist.txt_(23MB)-blue?style=for-the-badge&logo=download&logoColor=white" alt="Download Text Blocklist"></a>
<a href="https://github.com/tn3w/IPBlocklist/releases/latest/download/datacenter_asns.json"><img src="https://img.shields.io/badge/download-datacenter_asns.json-green?style=for-the-badge&logo=download&logoColor=white" alt="Download Datacenter ASNs"></a>
</p>

</div>

## 🚀 Key Features

- ✅ Fast IP lookups in <1ms using binary search
- ✅ 5.0M+ IPs and CIDR ranges from 128 threat intelligence feeds
- ✅ Malware C&C servers, botnets, spam networks, compromised hosts
- ✅ VPN providers, Tor nodes, datacenter/hosting ASNs, public proxies
- ✅ Optimized integer storage for minimal memory footprint
- ✅ Support for both IPv4 and IPv6
- ✅ Automated daily updates via GitHub Actions

## 📥 Download & Extract

Three artifacts are available: a binary database for programmatic lookups, a
scored text blocklist for firewall use, and a JSON list of normalized
datacenter ASNs.

```bash
# Binary format — for programmatic lookups (12MB)
wget https://github.com/tn3w/IPBlocklist/releases/latest/download/blocklist.bin

# Text format — for firewalls and ipset (23MB)
wget https://github.com/tn3w/IPBlocklist/releases/latest/download/blocklist.txt

# JSON format — normalized datacenter ASN list
wget https://github.com/tn3w/IPBlocklist/releases/latest/download/datacenter_asns.json
```

## 📊 Architecture

```
                                                 ┌─> blocklist.bin
feeds.json ──────> aggregator.py ────────────────┼─> datacenter_asns.json
    (config)           (processor)               └─> scoring ──> cidr_minimizer ──> blocklist.txt
                                                                                   (Rust, CIDR opt)
```

## 📖 Overview

IPBlocklist downloads threat intelligence from multiple sources (malware C&C servers, botnets, spam networks, VPN providers, Tor nodes, etc.) and converts them into a compact, searchable binary format. IP addresses and CIDR ranges are stored as delta-encoded integers for efficient binary search lookups.

The system uses open-source security feeds configured in feeds.json, which are processed by aggregator.py into a unified blocklist.bin file.

## 📁 Data Models

### feeds.json

Configuration file defining all threat intelligence sources. Each feed is an independent object with complete metadata.

**Structure**: Array of feed objects

```json
[
    {
        "name": "feodotracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": "Feodo Tracker - Botnet C&C",
        "regex": "^(?![#;/])([0-9a-fA-F:.]+(?:/\\d+)?)",
        "base_score": 1.0,
        "confidence": 0.95,
        "flags": ["is_malware", "is_botnet", "is_c2_server"],
        "categories": ["malware", "botnet"]
    }
]
```

**Required Fields**:

- `name`: Unique identifier for the feed
- `url`: Download URL for the threat list
- `description`: Human-readable description
- `regex`: Pattern to extract IPs/CIDRs from feed content
- `base_score`: Threat severity (0.0-1.0)
- `confidence`: Data reliability (0.0-1.0)
- `flags`: Boolean indicators (is_anycast, is_botnet, is_brute_force, is_c2_server, is_cdn, is_cloud, is_compromised, is_datacenter, is_forum_spammer, is_isp, is_malware, is_mobile, is_phishing, is_proxy, is_scanner, is_spammer, is_tor, is_vpn, is_web_attacker)
- `categories`: Categories for scoring (anonymizer, attacks, botnet, compromised, infrastructure, malware, spam)

**Optional Fields**:

- `provider_name`: VPN/hosting provider name

### blocklist.bin

Processed binary output with delta-encoded IP ranges for fast lookups.

**Structure**: Binary format with varint encoding

```
[4 bytes: timestamp (u32)]
[2 bytes: feed count (u16)]
For each feed:
  [1 byte: name length (u8)]
  [N bytes: feed name (utf-8)]
  [4 bytes: range count (u32)]
  For each range:
    [varint: from_delta]
    [varint: range_size]
```

**Encoding**:

- Timestamp: Unix timestamp as 32-bit unsigned integer
- Feed names: Length-prefixed UTF-8 strings
- Ranges: Delta-encoded start positions with varint compression
- Range size: End - start encoded as varint

**Integer Conversion**:

- IPv4: `10.0.0.1` → `167772161`
- IPv6: `2001:db8::1` → `42540766411282592856903984951653826561`
- CIDR: `10.0.0.0/27` → `(167772160, 167772191)` (network to broadcast)
- Single IP: Stored as range with size 0

### blocklist.txt

Scored, CIDR-minimized text blocklist for direct use with firewalls and IP filtering tools. Generated by `cidr_minimizer` (Rust) from the scored feed data.

**Generation Pipeline**:

1. Each feed's ranges are scored (`base_score × confidence`) and passed to a sweep-line algorithm
2. Overlapping scores are summed; regions above the threshold (0.5) become active ranges
3. IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are converted to native IPv4
4. Hierarchical CIDR promotion fills in blocks with ≥90% coverage (/27→/8 for IPv4, /124→/32 for IPv6)
5. Non-routable addresses are stripped (private, loopback, link-local, multicast, reserved, CGN, documentation)
6. Ranges are output in compact notation

**Format** (one entry per line, `#` comments at top):

| Notation    | Example                    | Meaning                |
| ----------- | -------------------------- | ---------------------- |
| Single IPv4 | `1.2.3.4`                  | Individual address     |
| IPv4 CIDR   | `1.2.3.0/24`               | Aligned CIDR block     |
| IPv4 range  | `1.2.3.1-1.2.3.254`        | Non-CIDR-aligned range |
| Single IPv6 | `2001:db8::1`              | Individual address     |
| IPv6 CIDR   | `2001:db8::/32`            | Aligned CIDR block     |
| IPv6 range  | `2001:db8::1-2001:db8::ff` | Non-CIDR-aligned range |

**Excluded Non-Routable Ranges**:

- IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`
- IPv6: `::/128`, `::1/128`, `64:ff9b:1::/48`, `100::/64`, `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `ff00::/8`

**Compatible with**: ipset, iptables (iprange module), nftables, pf

**Usage with nftables**:

```bash
nft add set inet filter blocklist { type ipv4_addr; flags interval; }
# Load entries (requires parsing script for mixed formats)
```

**Usage with ipset**:

```bash
ipset create blocklist hash:net
while IFS= read -r line; do
  [[ "$line" =~ ^# ]] && continue
  ipset add blocklist "$line" 2>/dev/null
done < blocklist.txt
```

## ⚙️ aggregator.py

Downloads and processes all feeds in parallel, handling multiple formats and edge cases.

**Features**:

- Parallel downloads with ThreadPoolExecutor (10 workers)
- IPv4/IPv6 support with embedded address extraction
- CIDR range expansion to [start, end] pairs
- ASN-to-prefix expansion for the `datacenter_asns` feed via RIPEstat
- Deduplication and sorting for binary search
- Regex-based parsing for diverse feed formats
- Proxy type integration from IP2X binary data

**Special Handling**:

- `datacenter_asns`: Resolves ASN numbers to IP ranges via RIPE API
- `proxy_types.bin`: Downloads pre-built proxy type ranges from [IP2X](https://github.com/tn3w/IP2X) (proxy types: PUB)
- IPv6 mapped addresses: Extracts embedded IPv4 (::ffff:192.0.2.1)
- 6to4 tunnels: Extracts IPv4 from 2002::/16 addresses

**Usage**:

```bash
python aggregator.py
```

**Output**: Creates/updates `blocklist.bin`, `blocklist.txt`, and `datacenter_asns.json`

`datacenter_asns.json` stores the normalized ASN values from the
`datacenter_asns` feed. Those ASNs are also expanded into announced prefixes
through the RIPEstat API and included in both blocklist outputs.

## 🐍 Python Lookup Examples

### Database Loader

```python
import struct
import ipaddress
from typing import Dict, List, Tuple, Optional


def read_varint(f) -> int:
    result = shift = 0
    while True:
        byte = f.read(1)[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result
        shift += 7


def binary_search(ranges: List[Tuple], target: int) -> Optional[int]:
    left, right = 0, len(ranges) - 1
    best_match = None
    best_size = float('inf')

    while left <= right:
        mid = (left + right) // 2
        start, end = ranges[mid]

        if start <= target <= end:
            size = end - start
            if size < best_size:
                best_size = size
                best_match = mid
            left = mid + 1
        elif target < start:
            right = mid - 1
        else:
            left = mid + 1

    return best_match


class BlocklistLoader:
    def __init__(self, path: str = "blocklist.bin"):
        self.feeds: Dict[str, List[Tuple[int, int]]] = {}
        self.timestamp: int = 0
        self._load(path)

    def _load(self, path: str):
        with open(path, "rb") as f:
            self.timestamp = struct.unpack("<I", f.read(4))[0]
            feed_count = struct.unpack("<H", f.read(2))[0]

            for _ in range(feed_count):
                name_len = struct.unpack("<B", f.read(1))[0]
                feed_name = f.read(name_len).decode("utf-8")
                range_count = struct.unpack("<I", f.read(4))[0]

                ranges = []
                current = 0
                for _ in range(range_count):
                    current += read_varint(f)
                    size = read_varint(f)
                    ranges.append((current, current + size))

                self.feeds[feed_name] = ranges

    def check_ip(self, ip: str) -> List[str]:
        target = int(ipaddress.ip_address(ip))
        matches = []

        for feed_name, ranges in self.feeds.items():
            if binary_search(ranges, target) is not None:
                matches.append(feed_name)

        return matches


blocklist = BlocklistLoader()
result = blocklist.check_ip("8.8.8.8")
print(result)
```

### Batch Lookup

```python
def check_batch(blocklist: BlocklistLoader, ip_list: List[str]) -> Dict[str, List[str]]:
    results = {}
    for ip in ip_list:
        results[ip] = blocklist.check_ip(ip)
    return results


ips = ["10.0.0.1", "192.168.1.1", "8.8.8.8"]
results = check_batch(blocklist, ips)
for ip, feeds in results.items():
    print(f"{ip}: {feeds}")
```

### Datacenter ASN Lookup

```python
import json

def load_datacenter_asns(asn_file="datacenter_asns.json"):
    """Load datacenter ASNs into a set for O(1) lookups."""
    try:
        with open(asn_file) as f:
            return set(json.load(f))
    except Exception as e:
        print(f"Error loading ASNs: {e}")
        return set()

def is_datacenter_asn(asn, asns=None):
    """Check if ASN belongs to a datacenter."""
    if not asns:
        asns = load_datacenter_asns()
    return asn.replace("AS", "").strip() in asns

asns = load_datacenter_asns()
for asn in ["AS16509", "AS13335", "AS15169"]:
    result = "is" if is_datacenter_asn(asn, asns) else "is not"
    print(f"{asn} {result} a datacenter ASN")
```

### Reputation Scoring

```python
import json


with open("feeds.json") as f:
    feeds_config = json.load(f)

sources = {feed["name"]: feed for feed in feeds_config}


def check_ip_with_reputation(blocklist: BlocklistLoader, ip: str) -> Dict:
    matches = blocklist.check_ip(ip)

    if not matches:
        return {"ip": ip, "score": 0.0, "feeds": []}

    flags = {}
    scores = {
        "anonymizer": [], "attacks": [], "botnet": [],
        "compromised": [], "infrastructure": [], "malware": [], "spam": []
    }

    for list_name in matches:
        source = sources.get(list_name)
        if not source:
            continue

        for flag in source.get("flags", []):
            flags[flag] = True

        provider = source.get("provider_name")
        if provider:
            flags["vpn_provider"] = provider

        base_score = source.get("base_score", 0.5)
        for category in source.get("categories", []):
            if category in scores:
                scores[category].append(base_score)

    total = 0.0
    for category_scores in scores.values():
        if not category_scores:
            continue
        combined = 1.0
        for score in sorted(category_scores, reverse=True):
            combined *= 1.0 - score
        total += 1.0 - combined

    return {
        "ip": ip,
        "score": min(total / 1.5, 1.0),
        "feeds": matches,
        **flags
    }


result = check_ip_with_reputation(blocklist, "8.8.8.8")
print(json.dumps(result, indent=2))
```

## ⚡ Performance Characteristics

**Dataset Statistics**:

- Total feeds: 128
- Individual IPs: 4.4M (4.4M IPv4, 6k IPv6)
- CIDR ranges: 552K (545K IPv4, 7K IPv6)
- Proxy type ranges: 4.1M (from IP2X)
- Total entries: 9.1M
- File size: 12MB (compressed with varint encoding)

**Lookup Complexity**:

- Binary search: O(log n) per feed
- Typical lookup: <1ms for 128 feeds with 9.1M entries

**Memory Usage**:

- Delta encoding: ~2-3 bytes per range (varint compressed)
- Feed names: Length-prefixed UTF-8 strings
- Total memory: ~12MB loaded in RAM

## 💡 Use Cases

- **API Rate Limiting**: Block known malicious IPs
- **Fraud Detection**: Flag VPN/proxy/datacenter traffic
- **Security Analytics**: Enrich logs with threat intelligence
- **Access Control**: Restrict Tor exit nodes or anonymizers
- **Compliance**: Block traffic from sanctioned networks

## 📜 License

Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
