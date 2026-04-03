import json
import time
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import struct
import re
import subprocess
import os


def parse_ip(ip_str):
    try:
        if "/" in ip_str:
            return ipaddress.ip_network(ip_str, strict=False)
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def parse_line(line, regex):
    matches = re.findall(regex, line)
    results = []
    for match in matches:
        if isinstance(match, str):
            results.append(match)
        elif isinstance(match, tuple):
            results.append(next((group for group in match if group), None))
    return results


def download_source(url, timeout=30):
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content = response.read().decode("utf-8", errors="ignore")
                return content.splitlines()
        except Exception as error:
            print(f"Error downloading {url} (attempt {attempt}/3): {error}")
            if attempt < 3:
                time.sleep(1)
    return []


def extract_feed_entries(source):
    entries = []

    for line in download_source(source["url"]):
        entries.extend(parse_line(line, source["regex"]))

    return entries


def download_single_list(source):
    return source["name"], extract_feed_entries(source)


def normalize_asn(asn):
    asn_value = str(asn).upper().removeprefix("AS").strip()
    return asn_value if asn_value.isdigit() else None


def lookup_asn_prefixes(asn):
    asn_num = normalize_asn(asn)
    if asn_num is None:
        return []

    url = (
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource="
        f"AS{asn_num}"
    )

    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("status") != "ok":
                    return []

                prefixes = data.get("data", {}).get("prefixes", [])
                return [prefix["prefix"] for prefix in prefixes if "prefix" in prefix]
        except Exception as error:
            print(
                f"Error retrieving AS{asn_num} "
                f"(attempt {attempt}/3): {error}"
            )
            if attempt < 3:
                time.sleep(1)

    print(f"Failed to retrieve ranges for AS{asn_num} after 3 attempts")
    return []


def download_datacenter_asn_feed(source):
    asns = []
    for asn in extract_feed_entries(source):
        normalized_asn = normalize_asn(asn)
        if normalized_asn is not None:
            asns.append(normalized_asn)

    unique_asns = sorted(set(asns))
    prefixes = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(lookup_asn_prefixes, asn): asn for asn in unique_asns
        }
        for future in as_completed(futures):
            asn = futures[future]
            asn_prefixes = future.result()
            prefixes.extend(asn_prefixes)
            print(f"Resolved AS{asn}: {len(asn_prefixes)} prefixes")

    return source["name"], prefixes, unique_asns


def save_datacenter_asns(asns, path="datacenter_asns.json"):
    with open(path, "w") as file:
        json.dump(asns, file, indent=2)
        file.write("\n")

    print(f"Saved {path} with {len(asns)} ASNs")


def download_all_feeds(sources):
    feeds = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(download_single_list, source): source for source in sources
        }
        for future in as_completed(futures):
            name, ips = future.result()
            feeds[name] = ips
            print(f"Downloaded {name}: {len(ips)} entries")
    return feeds


def write_varint(f, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        f.write(bytes([byte]))
        if value == 0:
            break


def process_feeds(feeds):
    processed = {}
    for list_name, ip_strings in feeds.items():
        ranges = []

        for ip_str in ip_strings:
            if not ip_str:
                continue
            if "-" in ip_str and ip_str.count("-") == 1:
                parts = ip_str.split("-")
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    ranges.append((start, end))
                    continue
                except ValueError:
                    pass
            parsed = parse_ip(ip_str)
            if parsed is None:
                continue
            if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                start = int(parsed.network_address)
                end = int(parsed.broadcast_address)
                ranges.append((start, end))
            elif isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                addr = int(parsed)
                ranges.append((addr, addr))

        ranges = sorted(set(ranges))
        processed[list_name] = ranges
    return processed


def read_varint(f):
    result = shift = 0
    while True:
        byte = f.read(1)[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result
        shift += 7


def download_proxy_types():
    url = "https://github.com/tn3w/IP2X/releases/latest/download/proxy_types.bin"
    print(f"Downloading proxy_types.bin...")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
    except Exception as error:
        print(f"Error downloading proxy_types.bin: {error}")
        return {}

    feeds = {}
    offset = 0
    type_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    for _ in range(type_count):
        name_len = struct.unpack_from("<B", data, offset)[0]
        offset += 1
        proxy_type = data[offset : offset + name_len].decode("utf-8")
        offset += name_len
        range_count = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        ranges = []
        current = 0
        for _ in range(range_count):
            result = shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    break
                shift += 7
            current += result

            result = shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    break
                shift += 7
            size = result

            ranges.append((current, current + size))

        feed_name = f"proxy_{proxy_type.lower()}"
        feeds[feed_name] = ranges
        print(f"Loaded {feed_name}: {len(ranges)} ranges")

    return feeds


def main():
    with open("feeds.json") as file:
        sources = json.load(file)

    datacenter_source = next(
        (source for source in sources if source["name"] == "datacenter_asns"),
        None,
    )
    direct_sources = [
        source for source in sources if source["name"] != "datacenter_asns"
    ]

    print("Downloading feeds...")
    feeds = download_all_feeds(direct_sources)

    datacenter_asns = []
    if datacenter_source is not None:
        print("Resolving datacenter ASN ranges...")
        feed_name, prefixes, datacenter_asns = download_datacenter_asn_feed(
            datacenter_source
        )
        feeds[feed_name] = prefixes
        print(
            f"Resolved {len(datacenter_asns)} ASNs into {len(prefixes)} prefixes"
        )

    save_datacenter_asns(datacenter_asns)

    print("Processing feeds...")
    processed = process_feeds(feeds)

    print("Loading proxy types...")
    proxy_feeds = download_proxy_types()
    processed.update(proxy_feeds)

    with open("blocklist.bin", "wb") as f:
        f.write(struct.pack("<I", int(time.time())))
        f.write(struct.pack("<H", len(processed)))

        for list_name, ranges in processed.items():
            name_bytes = list_name.encode("utf-8")
            f.write(struct.pack("<B", len(name_bytes)))
            f.write(name_bytes)
            f.write(struct.pack("<I", len(ranges)))

            prev_from = 0
            for start, end in ranges:
                from_delta = start - prev_from
                range_size = end - start

                write_varint(f, from_delta)
                write_varint(f, range_size)

                prev_from = start

    print(f"Saved blocklist.bin with {len(processed)} feeds")

    print("Generating scored blocklist.txt...")
    generate_blocklist_txt(sources, processed)


def generate_blocklist_txt(sources, processed):
    score_map = {
        s["name"]: s.get("base_score", 0.5) * s.get("confidence", 0.5) for s in sources
    }
    score_map["proxy_pub"] = 0.7 * 0.9

    threshold = 0.5
    coverage_pct = 90

    ipv4_ranges = []
    ipv6_ranges = []

    for feed_name, ranges in processed.items():
        score = score_map.get(feed_name, 0.3)
        for start, end in ranges:
            if end <= 0xFFFFFFFF:
                ipv4_ranges.append((start, end, score))
            else:
                ipv6_ranges.append((start, end, score))

    buf = bytearray()
    buf.extend(struct.pack("<f", threshold))
    buf.extend(struct.pack("<B", coverage_pct))

    buf.extend(struct.pack("<I", len(ipv4_ranges)))
    for start, end, score in ipv4_ranges:
        buf.extend(struct.pack("<IIf", start, end, score))

    buf.extend(struct.pack("<I", len(ipv6_ranges)))
    for start, end, score in ipv6_ranges:
        buf.extend(
            struct.pack(
                "<16s16sf",
                start.to_bytes(16, "little"),
                end.to_bytes(16, "little"),
                score,
            )
        )

    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary = os.path.join(
        script_dir, "cidr_minimizer", "target", "release", "cidr_minimizer"
    )

    if not os.path.exists(binary):
        print(f"Building cidr_minimizer...")
        subprocess.run(
            ["cargo", "build", "--release"],
            cwd=os.path.join(script_dir, "cidr_minimizer"),
            check=True,
        )

    print(
        f"Running cidr_minimizer with {len(ipv4_ranges)} IPv4 + {len(ipv6_ranges)} IPv6 scored ranges..."
    )
    result = subprocess.run(
        [binary],
        input=bytes(buf),
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"cidr_minimizer failed: {result.stderr.decode()}")
        return

    output = result.stdout.decode()
    lines = [l for l in output.splitlines() if l.strip()]

    with open("blocklist.txt", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Saved blocklist.txt with {len(lines)} entries")


if __name__ == "__main__":
    main()
