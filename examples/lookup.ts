import { readFileSync } from "fs";
import { isIPv4 } from "net";

interface Feed {
    name: string;
    baseScore: number;
    confidence: number;
    flagsMask: number;
    categoriesMask: number;
    ipv4Starts: number[];
    ipv4Ends: number[];
    flags: string[];
    categories: string[];
}

interface Blocklist {
    timestamp: number;
    feeds: Feed[];
}

function load(path = "blocklist.bin"): Blocklist {
    const buf = readFileSync(path);
    let pos = 0;

    if (buf.toString("ascii", 0, 4) !== "IPBL") throw new Error("bad magic");
    pos = 4;
    if (buf[pos++] !== 2) throw new Error("bad version");
    const timestamp = buf.readUInt32LE(pos); pos += 4;

    const readStr = (): string => {
        const len = buf[pos++];
        const s = buf.toString("utf8", pos, pos + len);
        pos += len; return s;
    };

    const readVarint = (): bigint => {
        let result = 0n, shift = 0n;
        while (true) {
            const b = buf[pos++];
            result |= BigInt(b & 0x7F) << shift;
            if (!(b & 0x80)) return result;
            shift += 7n;
        }
    };

    const fc = buf[pos++];
    const flagTable = Array.from({ length: fc }, readStr);
    const cc = buf[pos++];
    const catTable = Array.from({ length: cc }, readStr);

    const feedCount = buf.readUInt16LE(pos); pos += 2;
    const feeds: Feed[] = [];

    for (let i = 0; i < feedCount; i++) {
        const name = readStr();
        const baseScore = buf[pos++];
        const confidence = buf[pos++];
        const flagsMask = buf.readUInt32LE(pos); pos += 4;
        const categoriesMask = buf[pos++];
        const rc = buf.readUInt32LE(pos); pos += 4;

        const ipv4Starts: number[] = [];
        const ipv4Ends: number[] = [];
        let current = 0n;

        for (let r = 0; r < rc; r++) {
            current += readVarint();
            const end = current + readVarint();
            if (end <= 0xFFFFFFFFn) {
                ipv4Starts.push(Number(current));
                ipv4Ends.push(Number(end));
            }
        }

        const flags = flagTable.filter((_, j) => flagsMask & (1 << j));
        const cats = catTable.filter((_, j) => categoriesMask & (1 << j));

        feeds.push({
            name, baseScore, confidence,
            flagsMask, categoriesMask,
            ipv4Starts, ipv4Ends,
            flags, categories: cats,
        });
    }

    return { timestamp, feeds };
}

function bisectRight(arr: number[], target: number): number {
    let lo = 0, hi = arr.length;
    while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (arr[mid] <= target) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

function ipv4ToInt(ip: string): number {
    const p = ip.split(".");
    return ((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0;
}

const args = process.argv.slice(2);
if (!args.length) {
    process.stderr.write("Usage: ts-node lookup.ts <ip> [<ip> ...]\n");
    process.exit(1);
}

const bl = load();

for (const ip of args) {
    if (!isIPv4(ip)) {
        console.log(`${ip}: invalid/unsupported IP`);
        continue;
    }

    const target = ipv4ToInt(ip);
    let found = false;

    for (const f of bl.feeds) {
        const idx = bisectRight(f.ipv4Starts, target) - 1;
        if (idx >= 0 && target <= f.ipv4Ends[idx]) {
            const score = (f.baseScore / 200) * (f.confidence / 200);
            const parts = [f.name, `score=${score.toFixed(2)}`];
            if (f.flags.length) parts.push(`flags=${f.flags.join(",")}`);
            if (f.categories.length)
                parts.push(`cats=${f.categories.join(",")}`);
            console.log(`${ip}: ${parts.join(" | ")}`);
            found = true;
        }
    }

    if (!found) console.log(`${ip}: no matches`);
}
