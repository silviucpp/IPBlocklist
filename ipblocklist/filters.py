"""Address-space filters applied to every feed before anything is published.

Derived from kboykov/Threatkill (Apache-2.0), see NOTICE.

Upstream lists sometimes contain private, reserved or documentation space
(by design or by accident). Those ranges can never describe a real remote
host, so they are always removed, and a single absurdly wide entry is treated
as an error rather than as data.
"""

from . import ranges as R

# Special-purpose IPv4 space (RFC 6890 and the IANA registry).
BOGONS_V4 = (
    "0.0.0.0/8",  # "this network"
    "10.0.0.0/8",  # RFC 1918
    "100.64.0.0/10",  # RFC 6598 carrier-grade NAT
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link local
    "172.16.0.0/12",  # RFC 1918
    "192.0.0.0/24",  # IETF protocol assignments
    "192.0.2.0/24",  # TEST-NET-1
    "192.88.99.0/24",  # deprecated 6to4 relay anycast
    "192.168.0.0/16",  # RFC 1918
    "198.18.0.0/15",  # benchmarking
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",  # TEST-NET-3
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved, including 255.255.255.255
)

# Only global unicast IPv6 (2000::/3) is kept, minus documentation space.
GLOBAL_V6 = ("2000::/3",)
BOGONS_V6 = (
    "2001:db8::/32",  # documentation
    "3fff::/20",  # documentation (RFC 9637)
)

# A single upstream entry wider than this is counted as ``too_broad`` and
# dropped: one bad line such as 0.0.0.0/1 would otherwise mark half the
# Internet for every consumer.
MIN_PREFIX = {R.V4: 8, R.V6: 16}
MAX_ENTRY_SIZE = {R.V4: 1 << (32 - MIN_PREFIX[R.V4]), R.V6: 1 << (128 - MIN_PREFIX[R.V6])}


class AddressFilter:
    def __init__(self):
        self.deny = {
            R.V4: R.from_networks(BOGONS_V4),
            R.V6: R.from_networks(BOGONS_V6),
        }
        self.keep_v6 = R.from_networks(GLOBAL_V6)

    def apply(self, version, merged_ranges):
        """Return ``merged_ranges`` with bogons removed."""
        result = merged_ranges
        if version == R.V6:
            result = R.intersect(result, self.keep_v6)
        return R.subtract(result, self.deny[version])
