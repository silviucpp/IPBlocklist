import std.stdio, std.file, std.conv, std.algorithm, std.array,
       std.string, std.format;

struct Feed {
    string name;
    ubyte baseScore, confidence;
    uint flagsMask;
    ubyte categoriesMask;
    ulong[] ipv4Starts, ipv4Ends;
    string[] flags, categories;
}

ulong readVarint(ref const(ubyte)[] data) {
    ulong result = 0;
    int shift = 0;
    while (true) {
        ubyte b = data[0]; data = data[1..$];
        result |= cast(ulong)(b & 0x7F) << shift;
        if (!(b & 0x80)) return result;
        shift += 7;
    }
}

string readStr(ref const(ubyte)[] data) {
    ubyte len = data[0]; data = data[1..$];
    auto s = cast(string)data[0..len].dup;
    data = data[len..$];
    return s;
}

T readLE(T)(ref const(ubyte)[] data) {
    T v = *cast(T*)(data.ptr);
    data = data[T.sizeof..$];
    return v;
}

Feed[] load(string path = "blocklist.bin") {
    auto data = cast(const(ubyte)[])std.file.read(path);
    assert(cast(string)data[0..4] == "IPBL");
    data = data[4..$];
    assert(data[0] == 2); data = data[1..$];
    data = data[4..$]; // timestamp

    ubyte fc = data[0]; data = data[1..$];
    string[] flagTable;
    foreach (_; 0..fc) flagTable ~= readStr(data);

    ubyte cc = data[0]; data = data[1..$];
    string[] catTable;
    foreach (_; 0..cc) catTable ~= readStr(data);

    ushort feedCount = readLE!ushort(data);
    Feed[] feeds;

    foreach (_; 0..feedCount) {
        Feed f;
        f.name = readStr(data);
        f.baseScore = data[0]; data = data[1..$];
        f.confidence = data[0]; data = data[1..$];
        f.flagsMask = readLE!uint(data);
        f.categoriesMask = data[0]; data = data[1..$];
        uint rc = readLE!uint(data);

        ulong current = 0;
        foreach (__; 0..rc) {
            current += readVarint(data);
            ulong size = readVarint(data);
            ulong end = current + size;
            if (end <= 0xFFFFFFFF) {
                f.ipv4Starts ~= current;
                f.ipv4Ends ~= end;
            }
        }

        foreach (i; 0..flagTable.length)
            if (f.flagsMask & (1 << i))
                f.flags ~= flagTable[i];
        foreach (i; 0..catTable.length)
            if (f.categoriesMask & (1 << i))
                f.categories ~= catTable[i];

        feeds ~= f;
    }
    return feeds;
}

size_t bisectRight(const ulong[] arr, ulong target) {
    size_t lo = 0, hi = arr.length;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (arr[mid] <= target) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

void main(string[] args) {
    if (args.length < 2) {
        stderr.writeln("Usage: lookup <ip> [<ip> ...]");
        return;
    }

    auto feeds = load();

    foreach (ip; args[1..$]) {
        auto parts = ip.split(".");
        if (parts.length != 4) {
            writefln("%s: invalid IP", ip); continue;
        }
        ulong target;
        try {
            foreach (p; parts)
                target = (target << 8) | to!ulong(p);
        } catch (Exception) {
            writefln("%s: invalid IP", ip); continue;
        }

        bool found = false;
        foreach (ref f; feeds) {
            auto idx = bisectRight(f.ipv4Starts, target);
            if (idx > 0 && target <= f.ipv4Ends[idx - 1]) {
                double score = (f.baseScore / 200.0)
                             * (f.confidence / 200.0);
                auto p = [f.name, format("score=%.2f", score)];
                if (f.flags.length)
                    p ~= "flags=" ~ f.flags.join(",");
                if (f.categories.length)
                    p ~= "cats=" ~ f.categories.join(",");
                writefln("%s: %s", ip, p.join(" | "));
                found = true;
            }
        }
        if (!found) writefln("%s: no matches", ip);
    }
}
