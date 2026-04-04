require "io"
require "socket"

struct Feed
  property name : String
  property base_score : UInt8
  property confidence : UInt8
  property flags_mask : UInt32
  property categories_mask : UInt8
  property ipv4_starts : Array(UInt64)
  property ipv4_ends : Array(UInt64)
  property flags : Array(String)
  property categories : Array(String)

  def initialize(@name, @base_score, @confidence, @flags_mask,
                 @categories_mask, @ipv4_starts, @ipv4_ends,
                 @flags, @categories)
  end
end

def read_varint(io) : UInt64
  result = 0_u64
  shift = 0
  loop do
    byte = io.read_byte.not_nil!
    result |= (byte & 0x7F).to_u64 << shift
    return result if byte & 0x80 == 0
    shift += 7
  end
end

def read_str(io) : String
  len = io.read_byte.not_nil!
  io.read_string(len)
end

def load(path = "blocklist.bin") : Array(Feed)
  File.open(path, "rb") do |f|
    magic = Bytes.new(4)
    f.read_fully(magic)
    raise "invalid magic" unless String.new(magic) == "IPBL"
    raise "bad version" unless f.read_byte == 2
    f.read_bytes(UInt32, IO::ByteFormat::LittleEndian) # timestamp

    fc = f.read_byte.not_nil!
    flag_table = (0...fc).map { read_str(f) }
    cc = f.read_byte.not_nil!
    cat_table = (0...cc).map { read_str(f) }

    feed_count = f.read_bytes(
      UInt16, IO::ByteFormat::LittleEndian
    )
    feeds = Array(Feed).new

    feed_count.times do
      name = read_str(f)
      bs = f.read_byte.not_nil!
      co = f.read_byte.not_nil!
      fm = f.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
      cm = f.read_byte.not_nil!
      rc = f.read_bytes(UInt32, IO::ByteFormat::LittleEndian)

      v4s = Array(UInt64).new
      v4e = Array(UInt64).new
      current = 0_u64

      rc.times do
        current &+= read_varint(f)
        size = read_varint(f)
        en = current &+ size
        if en <= 0xFFFFFFFF_u64
          v4s << current; v4e << en
        end
      end

      mf = flag_table.each_with_index.select { |_, i|
        fm & (1_u32 << i) != 0
      }.map(&.first).to_a
      mc = cat_table.each_with_index.select { |_, i|
        cm & (1_u8 << i) != 0
      }.map(&.first).to_a

      feeds << Feed.new(name, bs, co, fm, cm, v4s, v4e, mf, mc)
    end

    return feeds
  end
end

def bisect_right(arr, target)
  lo, hi = 0, arr.size
  while lo < hi
    mid = (lo + hi) // 2
    if arr[mid] <= target
      lo = mid + 1
    else
      hi = mid
    end
  end
  lo
end

if ARGV.empty?
  STDERR.puts "Usage: crystal lookup.cr <ip> [<ip> ...]"
  exit 1
end

feeds = load

ARGV.each do |ip|
  parts = ip.split(".")
  unless parts.size == 4
    puts "#{ip}: invalid IP"; next
  end

  target = 0_u64
  parts.each { |p| target = (target << 8) | p.to_u64 }

  found = false
  feeds.each do |f|
    idx = bisect_right(f.ipv4_starts, target) - 1
    if idx >= 0 && target <= f.ipv4_ends[idx]
      score = (f.base_score / 200.0) * (f.confidence / 200.0)
      p = [f.name, "score=#{"%.2f" % score}"]
      p << "flags=#{f.flags.join(",")}" unless f.flags.empty?
      p << "cats=#{f.categories.join(",")}" unless f.categories.empty?
      puts "#{ip}: #{p.join(" | ")}"
      found = true
    end
  end

  puts "#{ip}: no matches" unless found
end
