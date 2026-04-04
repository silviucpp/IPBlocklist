require 'ipaddr'

def read_varint(f)
  result = shift = 0
  loop do
    b = f.readbyte
    result |= (b & 0x7F) << shift
    return result if b & 0x80 == 0
    shift += 7
  end
end

def load(path = "blocklist.bin")
  File.open(path, "rb") do |f|
    raise "bad magic" unless f.read(4) == "IPBL"
    raise "bad version" unless f.readbyte == 2
    timestamp = f.read(4).unpack1("V")

    flags = Array.new(f.readbyte) { n = f.readbyte; f.read(n) }
    cats = Array.new(f.readbyte) { n = f.readbyte; f.read(n) }
    feed_count = f.read(2).unpack1("v")

    feeds = feed_count.times.map do
      name_len = f.readbyte
      name = f.read(name_len)
      bs, co = f.readbyte, f.readbyte
      fm = f.read(4).unpack1("V")
      cm = f.readbyte
      rc = f.read(4).unpack1("V")
      v4s, v4e, v6s, v6e, cur = [], [], [], [], 0
      rc.times do
        cur += read_varint(f)
        en = cur + read_varint(f)
        if en <= 0xFFFFFFFF
          v4s << cur; v4e << en
        else
          v6s << cur; v6e << en
        end
      end
      { name: name, bs: bs, co: co, fm: fm, cm: cm,
        v4s: v4s, v4e: v4e, v6s: v6s, v6e: v6e,
        flags: flags, cats: cats }
    end

    [timestamp, feeds]
  end
end

def bisect_right(arr, target)
  lo, hi = 0, arr.size
  while lo < hi
    mid = (lo + hi) / 2
    arr[mid] <= target ? lo = mid + 1 : hi = mid
  end
  lo
end

_, feeds = load
ARGV.each do |ip_str|
  begin
    addr = IPAddr.new(ip_str)
  rescue
    puts "#{ip_str}: invalid IP"; next
  end

  target = addr.to_i
  v4 = addr.ipv4?
  found = false

  feeds.each do |f|
    s, e = v4 ? [f[:v4s], f[:v4e]] : [f[:v6s], f[:v6e]]
    idx = bisect_right(s, target) - 1
    next unless idx >= 0 && target <= e[idx]

    score = (f[:bs] / 200.0) * (f[:co] / 200.0)
    fl = f[:flags].each_index.select { |i| f[:fm] & (1 << i) != 0 }
         .map { |i| f[:flags][i] }.join(",")
    ca = f[:cats].each_index.select { |i| f[:cm] & (1 << i) != 0 }
         .map { |i| f[:cats][i] }.join(",")
    parts = ["#{f[:name]}", "score=#{'%.2f' % score}"]
    parts << "flags=#{fl}" unless fl.empty?
    parts << "cats=#{ca}" unless ca.empty?
    puts "#{ip_str}: #{parts.join(' | ')}"
    found = true
  end

  puts "#{ip_str}: no matches" unless found
end
