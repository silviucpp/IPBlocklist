#!/usr/bin/env lua
local function read_varint(f)
    local result, shift = 0, 0
    while true do
        local byte = f:read(1):byte()
        result = result | ((byte & 0x7F) << shift)
        if byte & 0x80 == 0 then return result end
        shift = shift + 7
    end
end

local function read_u16(f)
    local b = f:read(2)
    return b:byte(1) | (b:byte(2) << 8)
end

local function read_u32(f)
    local b = f:read(4)
    return b:byte(1) | (b:byte(2) << 8)
         | (b:byte(3) << 16) | (b:byte(4) << 24)
end

local function read_str(f)
    local len = f:read(1):byte()
    return f:read(len)
end

local function load(path)
    local f = assert(io.open(path or "blocklist.bin", "rb"))
    assert(f:read(4) == "IPBL")
    assert(f:read(1):byte() == 2)
    local timestamp = read_u32(f)

    local flag_count = f:read(1):byte()
    local flags = {}
    for i = 1, flag_count do flags[i] = read_str(f) end

    local cat_count = f:read(1):byte()
    local cats = {}
    for i = 1, cat_count do cats[i] = read_str(f) end

    local feed_count = read_u16(f)
    local feeds = {}

    for i = 1, feed_count do
        local name = read_str(f)
        local bs = f:read(1):byte()
        local co = f:read(1):byte()
        local fm = read_u32(f)
        local cm = f:read(1):byte()
        local rc = read_u32(f)

        local v4s, v4e = {}, {}
        local current = 0
        for _ = 1, rc do
            current = current + read_varint(f)
            local size = read_varint(f)
            local en = current + size
            if en <= 0xFFFFFFFF then
                v4s[#v4s + 1] = current
                v4e[#v4e + 1] = en
            end
        end

        local mf = {}
        for j = 1, #flags do
            if fm & (1 << (j - 1)) ~= 0 then mf[#mf+1] = flags[j] end
        end
        local mc = {}
        for j = 1, #cats do
            if cm & (1 << (j - 1)) ~= 0 then mc[#mc+1] = cats[j] end
        end

        feeds[i] = {
            name = name, bs = bs, co = co,
            flags = mf, cats = mc, v4s = v4s, v4e = v4e,
        }
    end
    f:close()
    return timestamp, feeds
end

local function bisect_right(arr, target)
    local lo, hi = 1, #arr + 1
    while lo < hi do
        local mid = math.floor((lo + hi) / 2)
        if arr[mid] <= target then lo = mid + 1 else hi = mid end
    end
    return lo
end

local function parse_ipv4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return (tonumber(a) << 24) | (tonumber(b) << 16)
         | (tonumber(c) << 8) | tonumber(d)
end

if #arg < 1 then
    io.stderr:write("Usage: lua lookup.lua <ip> [<ip> ...]\n")
    os.exit(1)
end

local _, feeds = load()

for _, ip in ipairs(arg) do
    local target = parse_ipv4(ip)
    if not target then
        print(ip .. ": invalid/unsupported IP")
        goto continue
    end

    local found = false
    for _, feed in ipairs(feeds) do
        local idx = bisect_right(feed.v4s, target) - 1
        if idx >= 1 and target <= feed.v4e[idx] then
            local score = (feed.bs / 200.0) * (feed.co / 200.0)
            local parts = { feed.name,
                string.format("score=%.2f", score) }
            if #feed.flags > 0 then
                parts[#parts+1] = "flags=" ..
                    table.concat(feed.flags, ",")
            end
            if #feed.cats > 0 then
                parts[#parts+1] = "cats=" ..
                    table.concat(feed.cats, ",")
            end
            print(ip .. ": " .. table.concat(parts, " | "))
            found = true
        end
    end

    if not found then print(ip .. ": no matches") end
    ::continue::
end
