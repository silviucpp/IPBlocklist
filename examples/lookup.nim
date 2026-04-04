import sys, os, strutils, algorithm

type Feed = object
  name: string
  baseScore, confidence: uint8
  flagsMask: uint32
  categoriesMask: uint8
  ipv4Starts, ipv4Ends: seq[uint64]
  flags, categories: seq[string]

proc readVarint(data: openArray[uint8], pos: var int): uint64 =
  var shift = 0
  while true:
    let b = data[pos]; inc pos
    result = result or (uint64(b and 0x7F) shl shift)
    if (b and 0x80) == 0: return
    shift += 7

proc readStr(data: openArray[uint8], pos: var int): string =
  let length = int(data[pos]); inc pos
  result = newString(length)
  for i in 0..<length: result[i] = char(data[pos + i])
  pos += length

proc readU16(data: openArray[uint8], pos: var int): uint16 =
  result = uint16(data[pos]) or (uint16(data[pos+1]) shl 8)
  pos += 2

proc readU32(data: openArray[uint8], pos: var int): uint32 =
  result = uint32(data[pos]) or (uint32(data[pos+1]) shl 8) or
           (uint32(data[pos+2]) shl 16) or (uint32(data[pos+3]) shl 24)
  pos += 4

proc load(path = "blocklist.bin"): seq[Feed] =
  let data = cast[seq[uint8]](readFile(path))
  var pos = 4
  assert data[pos] == 2; inc pos
  pos += 4 # timestamp

  let fc = int(data[pos]); inc pos
  var flagTable = newSeq[string](fc)
  for i in 0..<fc: flagTable[i] = readStr(data, pos)

  let cc = int(data[pos]); inc pos
  var catTable = newSeq[string](cc)
  for i in 0..<cc: catTable[i] = readStr(data, pos)

  let feedCount = int(readU16(data, pos))
  result = newSeq[Feed](feedCount)

  for fi in 0..<feedCount:
    var f: Feed
    f.name = readStr(data, pos)
    f.baseScore = data[pos]; inc pos
    f.confidence = data[pos]; inc pos
    f.flagsMask = readU32(data, pos)
    f.categoriesMask = data[pos]; inc pos
    let rc = int(readU32(data, pos))

    var current: uint64 = 0
    for _ in 0..<rc:
      current += readVarint(data, pos)
      let size = readVarint(data, pos)
      let en = current + size
      if en <= 0xFFFFFFFF'u64:
        f.ipv4Starts.add current
        f.ipv4Ends.add en

    for i in 0..<flagTable.len:
      if (f.flagsMask and (1'u32 shl i)) != 0:
        f.flags.add flagTable[i]
    for i in 0..<catTable.len:
      if (f.categoriesMask and (1'u8 shl i)) != 0:
        f.categories.add catTable[i]

    result[fi] = f

proc bisectRight(arr: seq[uint64], target: uint64): int =
  var lo = 0; var hi = arr.len
  while lo < hi:
    let mid = lo + (hi - lo) div 2
    if arr[mid] <= target: lo = mid + 1
    else: hi = mid
  lo

proc parseIPv4(s: string): uint64 =
  let parts = s.split('.')
  assert parts.len == 4
  for p in parts:
    result = (result shl 8) or uint64(parseInt(p))

when isMainModule:
  if paramCount() < 1:
    quit "Usage: lookup <ip> [<ip> ...]"

  let feeds = load()

  for i in 1..paramCount():
    let ip = paramStr(i)
    var target: uint64
    try: target = parseIPv4(ip)
    except: echo ip, ": invalid IP"; continue

    var found = false
    for f in feeds:
      let idx = bisectRight(f.ipv4Starts, target) - 1
      if idx >= 0 and target <= f.ipv4Ends[idx]:
        let score = (float(f.baseScore) / 200.0) *
                    (float(f.confidence) / 200.0)
        var parts = @[f.name, "score=" & formatFloat(score, ffDecimal, 2)]
        if f.flags.len > 0:
          parts.add "flags=" & f.flags.join(",")
        if f.categories.len > 0:
          parts.add "cats=" & f.categories.join(",")
        echo ip, ": ", parts.join(" | ")
        found = true

    if not found:
      echo ip, ": no matches"
