import Foundation

struct Feed {
    let name: String
    let baseScore: UInt8
    let confidence: UInt8
    let flagsMask: UInt32
    let categoriesMask: UInt8
    let ipv4Starts: [UInt64]
    let ipv4Ends: [UInt64]
}

struct Blocklist {
    let timestamp: UInt32
    let flags: [String]
    let categories: [String]
    let feeds: [Feed]
}

class Reader {
    let data: Data
    var pos: Int = 0

    init(_ data: Data) { self.data = data }

    func readU8() -> UInt8 {
        let v = data[pos]; pos += 1; return v
    }

    func readU16() -> UInt16 {
        let v = data[pos..<pos+2].withUnsafeBytes {
            $0.load(as: UInt16.self)
        }
        pos += 2; return UInt16(littleEndian: v)
    }

    func readU32() -> UInt32 {
        let v = data[pos..<pos+4].withUnsafeBytes {
            $0.load(as: UInt32.self)
        }
        pos += 4; return UInt32(littleEndian: v)
    }

    func readStr() -> String {
        let len = Int(readU8())
        let s = String(data: data[pos..<pos+len], encoding: .utf8)!
        pos += len; return s
    }

    func readVarint() -> UInt64 {
        var result: UInt64 = 0; var shift: UInt64 = 0
        while true {
            let b = readU8()
            result |= UInt64(b & 0x7F) << shift
            if b & 0x80 == 0 { return result }
            shift += 7
        }
    }
}

func load(_ path: String) -> Blocklist {
    let data = try! Data(contentsOf: URL(fileURLWithPath: path))
    let r = Reader(data)

    assert(String(data: data[0..<4], encoding: .ascii) == "IPBL")
    r.pos = 4
    assert(r.readU8() == 2)
    let timestamp = r.readU32()

    let flags = (0..<r.readU8()).map { _ in r.readStr() }
    let cats = (0..<r.readU8()).map { _ in r.readStr() }
    let feedCount = r.readU16()

    var feeds: [Feed] = []
    for _ in 0..<feedCount {
        let name = r.readStr()
        let bs = r.readU8(), co = r.readU8()
        let fm = r.readU32(), cm = r.readU8()
        let rc = r.readU32()

        var v4s: [UInt64] = [], v4e: [UInt64] = []
        var current: UInt64 = 0
        for _ in 0..<rc {
            current &+= r.readVarint()
            let size = r.readVarint()
            let end = current &+ size
            if end <= 0xFFFFFFFF {
                v4s.append(current); v4e.append(end)
            }
        }
        feeds.append(Feed(
            name: name, baseScore: bs, confidence: co,
            flagsMask: fm, categoriesMask: cm,
            ipv4Starts: v4s, ipv4Ends: v4e
        ))
    }

    return Blocklist(
        timestamp: timestamp, flags: flags,
        categories: cats, feeds: feeds
    )
}

func bisectRight(_ arr: [UInt64], _ target: UInt64) -> Int {
    var lo = 0, hi = arr.count
    while lo < hi {
        let mid = lo + (hi - lo) / 2
        if arr[mid] <= target { lo = mid + 1 } else { hi = mid }
    }
    return lo
}

func ipv4ToInt(_ s: String) -> UInt64? {
    let parts = s.split(separator: ".").compactMap {
        UInt64($0)
    }
    guard parts.count == 4 else { return nil }
    return (parts[0] << 24) | (parts[1] << 16)
         | (parts[2] << 8) | parts[3]
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    print("Usage: lookup <ip> [<ip> ...]"); exit(1)
}

let bl = load("blocklist.bin")

for ip in args[1...] {
    guard let target = ipv4ToInt(ip) else {
        print("\(ip): invalid/unsupported IP"); continue
    }

    var found = false
    for feed in bl.feeds {
        let idx = bisectRight(feed.ipv4Starts, target) - 1
        if idx >= 0 && target <= feed.ipv4Ends[idx] {
            let score = Double(feed.baseScore) / 200.0
                      * Double(feed.confidence) / 200.0
            var parts = [feed.name, String(format: "score=%.2f", score)]
            let fl = bl.flags.enumerated()
                .filter { feed.flagsMask & (1 << $0.offset) != 0 }
                .map(\.element)
            if !fl.isEmpty { parts.append("flags=\(fl.joined(separator: ","))") }
            let ca = bl.categories.enumerated()
                .filter { feed.categoriesMask & (1 << $0.offset) != 0 }
                .map(\.element)
            if !ca.isEmpty { parts.append("cats=\(ca.joined(separator: ","))") }
            print("\(ip): \(parts.joined(separator: " | "))")
            found = true
        }
    }

    if !found { print("\(ip): no matches") }
}
