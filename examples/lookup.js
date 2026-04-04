import { readFileSync } from 'fs';
import { isIPv4 } from 'net';

function load(path) {
    const buf = readFileSync(path);
    let pos = 0;

    const magic = buf.toString('ascii', 0, 4);
    if (magic !== 'IPBL') throw new Error('invalid magic');
    pos = 4;

    const version = buf[pos++];
    if (version !== 2) throw new Error('unsupported version');

    const timestamp = buf.readUInt32LE(pos);
    pos += 4;

    const flagCount = buf[pos++];
    const flags = [];
    for (let i = 0; i < flagCount; i++) {
        const len = buf[pos++];
        flags.push(buf.toString('utf8', pos, pos + len));
        pos += len;
    }

    const catCount = buf[pos++];
    const categories = [];
    for (let i = 0; i < catCount; i++) {
        const len = buf[pos++];
        categories.push(buf.toString('utf8', pos, pos + len));
        pos += len;
    }

    const feedCount = buf.readUInt16LE(pos);
    pos += 2;
    const feeds = [];

    for (let i = 0; i < feedCount; i++) {
        const nameLen = buf[pos++];
        const name = buf.toString('utf8', pos, pos + nameLen);
        pos += nameLen;

        const baseScore = buf[pos++];
        const confidence = buf[pos++];
        const flagsMask = buf.readUInt32LE(pos);
        pos += 4;
        const categoriesMask = buf[pos++];
        const rangeCount = buf.readUInt32LE(pos);
        pos += 4;

        const ipv4Starts = [];
        const ipv4Ends = [];
        let current = 0n;

        for (let r = 0; r < rangeCount; r++) {
            let result = 0n,
                shift = 0n;
            while (true) {
                const byte = buf[pos++];
                result |= BigInt(byte & 0x7f) << shift;
                if (!(byte & 0x80)) break;
                shift += 7n;
            }
            current += result;

            result = 0n;
            shift = 0n;
            while (true) {
                const byte = buf[pos++];
                result |= BigInt(byte & 0x7f) << shift;
                if (!(byte & 0x80)) break;
                shift += 7n;
            }
            const end = current + result;

            if (end <= 0xffffffffn) {
                ipv4Starts.push(Number(current));
                ipv4Ends.push(Number(end));
            }
        }

        feeds.push({
            name,
            baseScore,
            confidence,
            flagsMask,
            categoriesMask,
            ipv4Starts,
            ipv4Ends,
        });
    }

    return { timestamp, flags, categories, feeds };
}

function bisectRight(arr, target) {
    let lo = 0,
        hi = arr.length;
    while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (arr[mid] <= target) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

function formatMatch(bl, feed) {
    const score = (feed.baseScore / 200) * (feed.confidence / 200);
    const parts = [feed.name, `score=${score.toFixed(2)}`];

    const matchedFlags = bl.flags.filter((_, i) => feed.flagsMask & (1 << i));
    if (matchedFlags.length) parts.push(`flags=${matchedFlags.join(',')}`);

    const matchedCats = bl.categories.filter((_, i) => feed.categoriesMask & (1 << i));
    if (matchedCats.length) parts.push(`cats=${matchedCats.join(',')}`);

    return parts.join(' | ');
}

function ipv4ToInt(ip) {
    const parts = ip.split('.');
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

const args = process.argv.slice(2);
if (!args.length) {
    console.error('Usage: node lookup.js <ip> [<ip> ...]');
    process.exit(1);
}

const bl = load('blocklist.bin');

for (const ip of args) {
    if (!isIPv4(ip)) {
        console.log(`${ip}: invalid/unsupported IP`);
        continue;
    }

    const target = ipv4ToInt(ip);
    let found = false;

    for (const feed of bl.feeds) {
        const idx = bisectRight(feed.ipv4Starts, target) - 1;
        if (idx >= 0 && target <= feed.ipv4Ends[idx]) {
            console.log(`${ip}: ${formatMatch(bl, feed)}`);
            found = true;
        }
    }

    if (!found) console.log(`${ip}: no matches`);
}
