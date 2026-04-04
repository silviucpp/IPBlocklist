const std = @import("std");
const mem = std.mem;
const fs = std.fs;

const Feed = struct {
    name: []const u8,
    base_score: u8,
    confidence: u8,
    flags_mask: u32,
    categories_mask: u8,
    ipv4_starts: []u64,
    ipv4_ends: []u64,
    ipv6_starts: []u128,
    ipv6_ends: []u128,
};

const Blocklist = struct {
    flags: [][]const u8,
    categories: [][]const u8,
    feeds: []Feed,
    arena: []u8,
};

fn readVarint(data: []const u8, pos: *usize) u128 {
    var result: u128 = 0;
    var shift: u7 = 0;
    while (true) {
        const byte = data[pos.*];
        pos.* += 1;
        result |= @as(u128, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) return result;
        shift +%= 7;
    }
}

fn readStr(data: []const u8, pos: *usize) []const u8 {
    const length = data[pos.*];
    pos.* += 1;
    const s = data[pos.* .. pos.* + length];
    pos.* += length;
    return s;
}

fn readU16(data: []const u8, pos: *usize) u16 {
    const v = mem.readInt(u16, data[pos.*..][0..2], .little);
    pos.* += 2;
    return v;
}

fn readU32(data: []const u8, pos: *usize) u32 {
    const v = mem.readInt(u32, data[pos.*..][0..4], .little);
    pos.* += 4;
    return v;
}

fn bisectRight(comptime T: type, starts: []const T, target: T) usize {
    var lo: usize = 0;
    var hi: usize = starts.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (starts[mid] <= target) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

fn parseIPv4(s: []const u8) ?u64 {
    var parts: [4]u8 = undefined;
    var idx: usize = 0;
    var acc: u16 = 0;
    for (s) |c| {
        if (c == '.') {
            if (idx >= 3) return null;
            parts[idx] = @intCast(acc);
            idx += 1;
            acc = 0;
        } else if (c >= '0' and c <= '9') {
            acc = acc * 10 + (c - '0');
            if (acc > 255) return null;
        } else return null;
    }
    if (idx != 3) return null;
    parts[3] = @intCast(acc);
    return @as(u64, parts[0]) << 24 |
        @as(u64, parts[1]) << 16 |
        @as(u64, parts[2]) << 8 |
        @as(u64, parts[3]);
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdout = std.io.getStdOut().writer();
    const args = try std.process.argsAlloc(allocator);

    if (args.len < 2) {
        try stdout.print("Usage: lookup <ip> [<ip> ...]\n", .{});
        return;
    }

    const data = try fs.cwd().readFileAlloc(
        allocator, "blocklist.bin", 512 * 1024 * 1024,
    );

    var pos: usize = 4;
    pos += 1;
    pos += 4;

    const flag_count = data[pos];
    pos += 1;
    const flags = try allocator.alloc([]const u8, flag_count);
    for (0..flag_count) |i| {
        flags[i] = readStr(data, &pos);
    }

    const cat_count = data[pos];
    pos += 1;
    const categories = try allocator.alloc([]const u8, cat_count);
    for (0..cat_count) |i| {
        categories[i] = readStr(data, &pos);
    }

    const feed_count = readU16(data, &pos);
    const feeds = try allocator.alloc(Feed, feed_count);

    for (0..feed_count) |fi| {
        const name = readStr(data, &pos);
        const base_score = data[pos];
        pos += 1;
        const confidence = data[pos];
        pos += 1;
        const flags_mask = readU32(data, &pos);
        const categories_mask = data[pos];
        pos += 1;
        const range_count = readU32(data, &pos);

        var v4s = std.ArrayList(u64).init(allocator);
        var v4e = std.ArrayList(u64).init(allocator);
        var v6s = std.ArrayList(u128).init(allocator);
        var v6e = std.ArrayList(u128).init(allocator);

        var current: u128 = 0;
        for (0..range_count) |_| {
            current += readVarint(data, &pos);
            const size = readVarint(data, &pos);
            const end = current + size;
            if (end <= 0xFFFFFFFF) {
                try v4s.append(@intCast(current));
                try v4e.append(@intCast(end));
            } else {
                try v6s.append(current);
                try v6e.append(end);
            }
        }

        feeds[fi] = .{
            .name = name,
            .base_score = base_score,
            .confidence = confidence,
            .flags_mask = flags_mask,
            .categories_mask = categories_mask,
            .ipv4_starts = v4s.items,
            .ipv4_ends = v4e.items,
            .ipv6_starts = v6s.items,
            .ipv6_ends = v6e.items,
        };
    }

    for (args[1..]) |arg| {
        if (parseIPv4(arg)) |target| {
            var found = false;
            for (feeds) |feed| {
                const idx = bisectRight(u64, feed.ipv4_starts, target);
                if (idx > 0 and target <= feed.ipv4_ends[idx - 1]) {
                    const score = @as(f64, @floatFromInt(feed.base_score)) / 200.0 *
                        @as(f64, @floatFromInt(feed.confidence)) / 200.0;
                    try stdout.print("{s}: {s} | score={d:.2}\n", .{ arg, feed.name, score });
                    found = true;
                }
            }
            if (!found) try stdout.print("{s}: no matches\n", .{arg});
        } else {
            try stdout.print("{s}: invalid/unsupported IP\n", .{arg});
        }
    }
}
