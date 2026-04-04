import 'dart:io';
import 'dart:typed_data';

class Feed {
  final String name;
  final int baseScore, confidence;
  final int flagsMask, categoriesMask;
  final List<int> ipv4Starts, ipv4Ends;
  final List<String> flags, categories;
  Feed(this.name, this.baseScore, this.confidence, this.flagsMask,
      this.categoriesMask, this.ipv4Starts, this.ipv4Ends,
      this.flags, this.categories);
}

class Reader {
  final ByteData data;
  int pos;
  Reader(this.data, [this.pos = 0]);

  int u8() => data.getUint8(pos++);
  int u16() { var v = data.getUint16(pos, Endian.little); pos += 2; return v; }
  int u32() { var v = data.getUint32(pos, Endian.little); pos += 4; return v; }

  String str() {
    var len = u8();
    var s = String.fromCharCodes(
        data.buffer.asUint8List(data.offsetInBytes + pos, len));
    pos += len;
    return s;
  }

  int varint() {
    int result = 0, shift = 0;
    while (true) {
      var b = u8();
      result |= (b & 0x7F) << shift;
      if (b & 0x80 == 0) return result;
      shift += 7;
    }
  }
}

List<Feed> load([String path = 'blocklist.bin']) {
  var bytes = File(path).readAsBytesSync();
  var r = Reader(ByteData.sublistView(bytes), 4);
  r.u8(); // version
  r.u32(); // timestamp

  var fc = r.u8();
  var flags = List.generate(fc, (_) => r.str());
  var cc = r.u8();
  var cats = List.generate(cc, (_) => r.str());

  var feedCount = r.u16();
  var feeds = <Feed>[];

  for (var i = 0; i < feedCount; i++) {
    var name = r.str();
    var bs = r.u8(), co = r.u8();
    var fm = r.u32(), cm = r.u8();
    var rc = r.u32();

    var v4s = <int>[], v4e = <int>[];
    var current = 0;
    for (var j = 0; j < rc; j++) {
      current += r.varint();
      var end = current + r.varint();
      if (end <= 0xFFFFFFFF) { v4s.add(current); v4e.add(end); }
    }

    var mf = [for (var k = 0; k < flags.length; k++)
      if (fm & (1 << k) != 0) flags[k]];
    var mc = [for (var k = 0; k < cats.length; k++)
      if (cm & (1 << k) != 0) cats[k]];

    feeds.add(Feed(name, bs, co, fm, cm, v4s, v4e, mf, mc));
  }
  return feeds;
}

int bisectRight(List<int> arr, int target) {
  var lo = 0, hi = arr.length;
  while (lo < hi) {
    var mid = (lo + hi) >> 1;
    if (arr[mid] <= target) lo = mid + 1; else hi = mid;
  }
  return lo;
}

int? parseIPv4(String s) {
  var parts = s.split('.');
  if (parts.length != 4) return null;
  try {
    return (int.parse(parts[0]) << 24) | (int.parse(parts[1]) << 16)
         | (int.parse(parts[2]) << 8) | int.parse(parts[3]);
  } catch (_) { return null; }
}

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Usage: dart lookup.dart <ip> [<ip> ...]');
    return;
  }

  var feeds = load();

  for (var ip in args) {
    var target = parseIPv4(ip);
    if (target == null) { print('$ip: invalid IP'); continue; }

    var found = false;
    for (var f in feeds) {
      var idx = bisectRight(f.ipv4Starts, target) - 1;
      if (idx >= 0 && target <= f.ipv4Ends[idx]) {
        var score = (f.baseScore / 200.0) * (f.confidence / 200.0);
        var parts = [f.name, 'score=${score.toStringAsFixed(2)}'];
        if (f.flags.isNotEmpty) parts.add('flags=${f.flags.join(",")}');
        if (f.categories.isNotEmpty)
          parts.add('cats=${f.categories.join(",")}');
        print('$ip: ${parts.join(" | ")}');
        found = true;
      }
    }
    if (!found) print('$ip: no matches');
  }
}
