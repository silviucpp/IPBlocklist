<?php
function readVarint(string $data, int &$pos): int {
    $result = $shift = 0;
    do {
        $byte = ord($data[$pos++]);
        $result |= ($byte & 0x7F) << $shift;
        $shift += 7;
    } while ($byte & 0x80);
    return $result;
}

function readStr(string $data, int &$pos): string {
    $len = ord($data[$pos++]);
    $s = substr($data, $pos, $len);
    $pos += $len;
    return $s;
}

function load(string $path = "blocklist.bin"): array {
    $data = file_get_contents($path);
    $pos = 0;

    if (substr($data, 0, 4) !== "IPBL") die("invalid magic\n");
    $pos = 4;
    if (ord($data[$pos++]) !== 2) die("bad version\n");

    $timestamp = unpack("V", $data, $pos)[1]; $pos += 4;

    $flagCount = ord($data[$pos++]);
    $flags = [];
    for ($i = 0; $i < $flagCount; $i++) $flags[] = readStr($data, $pos);

    $catCount = ord($data[$pos++]);
    $categories = [];
    for ($i = 0; $i < $catCount; $i++) $categories[] = readStr($data, $pos);

    $feedCount = unpack("v", $data, $pos)[1]; $pos += 2;
    $feeds = [];

    for ($i = 0; $i < $feedCount; $i++) {
        $name = readStr($data, $pos);
        $bs = ord($data[$pos++]);
        $co = ord($data[$pos++]);
        $fm = unpack("V", $data, $pos)[1]; $pos += 4;
        $cm = ord($data[$pos++]);
        $rc = unpack("V", $data, $pos)[1]; $pos += 4;

        $v4s = $v4e = [];
        $current = 0;
        for ($r = 0; $r < $rc; $r++) {
            $current += readVarint($data, $pos);
            $end = $current + readVarint($data, $pos);
            if ($end <= 0xFFFFFFFF) {
                $v4s[] = $current; $v4e[] = $end;
            }
        }

        $feeds[] = compact('name', 'bs', 'co', 'fm', 'cm', 'v4s', 'v4e');
    }

    return [$timestamp, $flags, $categories, $feeds];
}

function bisectRight(array $arr, int $target): int {
    $lo = 0; $hi = count($arr);
    while ($lo < $hi) {
        $mid = ($lo + $hi) >> 1;
        if ($arr[$mid] <= $target) $lo = $mid + 1;
        else $hi = $mid;
    }
    return $lo;
}

if ($argc < 2) { fwrite(STDERR, "Usage: php lookup.php <ip> [<ip> ...]\n"); exit(1); }

[$timestamp, $flags, $categories, $feeds] = load();

for ($a = 1; $a < $argc; $a++) {
    $ip = $argv[$a];
    $packed = @inet_pton($ip);
    if ($packed === false) { echo "$ip: invalid IP\n"; continue; }
    if (strlen($packed) !== 4) { echo "$ip: IPv6 not supported in this example\n"; continue; }

    $target = unpack("N", $packed)[1];
    $found = false;

    foreach ($feeds as $f) {
        $idx = bisectRight($f['v4s'], $target) - 1;
        if ($idx >= 0 && $target <= $f['v4e'][$idx]) {
            $score = ($f['bs'] / 200.0) * ($f['co'] / 200.0);
            $parts = [$f['name'], sprintf("score=%.2f", $score)];
            $fl = [];
            for ($i = 0; $i < count($flags); $i++)
                if ($f['fm'] & (1 << $i)) $fl[] = $flags[$i];
            if ($fl) $parts[] = "flags=" . implode(",", $fl);
            $ca = [];
            for ($i = 0; $i < count($categories); $i++)
                if ($f['cm'] & (1 << $i)) $ca[] = $categories[$i];
            if ($ca) $parts[] = "cats=" . implode(",", $ca);
            echo "$ip: " . implode(" | ", $parts) . "\n";
            $found = true;
        }
    }

    if (!$found) echo "$ip: no matches\n";
}
