import kotlin.io.path.Path
import kotlin.io.path.readBytes

data class Feed(
    val name: String, val baseScore: Int, val confidence: Int,
    val flagsMask: UInt, val categoriesMask: Int,
    val ipv4Starts: LongArray, val ipv4Ends: LongArray
)

data class Blocklist(
    val timestamp: Long, val flags: List<String>,
    val categories: List<String>, val feeds: List<Feed>
)

class Reader(private val data: ByteArray) {
    var pos = 0

    fun u8() = data[pos++].toInt() and 0xFF

    fun u16(): Int {
        val v = (data[pos].toInt() and 0xFF) or
                ((data[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2; return v
    }

    fun u32(): Long {
        val v = (data[pos].toLong() and 0xFF) or
            ((data[pos+1].toLong() and 0xFF) shl 8) or
            ((data[pos+2].toLong() and 0xFF) shl 16) or
            ((data[pos+3].toLong() and 0xFF) shl 24)
        pos += 4; return v
    }

    fun str(): String {
        val len = u8()
        val s = String(data, pos, len)
        pos += len; return s
    }

    fun varint(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
    }
}

fun load(path: String = "blocklist.bin"): Blocklist {
    val r = Reader(Path(path).readBytes())
    check(String(r.data, 0, 4) == "IPBL")
    r.pos = 4
    check(r.u8() == 2)
    val timestamp = r.u32()

    val flags = (0 until r.u8()).map { r.str() }
    val cats = (0 until r.u8()).map { r.str() }
    val feedCount = r.u16()

    val feeds = (0 until feedCount).map {
        val name = r.str()
        val bs = r.u8(); val co = r.u8()
        val fm = r.u32().toUInt(); val cm = r.u8()
        val rc = r.u32().toInt()
        val v4s = mutableListOf<Long>()
        val v4e = mutableListOf<Long>()
        var current = 0L
        repeat(rc) {
            current += r.varint()
            val end = current + r.varint()
            if (end <= 0xFFFFFFFFL) {
                v4s.add(current); v4e.add(end)
            }
        }
        Feed(name, bs, co, fm, cm,
            v4s.toLongArray(), v4e.toLongArray())
    }

    return Blocklist(timestamp, flags, cats, feeds)
}

fun bisectRight(arr: LongArray, target: Long): Int {
    var lo = 0; var hi = arr.size
    while (lo < hi) {
        val mid = (lo + hi) ushr 1
        if (arr[mid] <= target) lo = mid + 1 else hi = mid
    }
    return lo
}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("Usage: kotlin lookup <ip> [<ip> ...]")
        return
    }

    val bl = load()

    for (ip in args) {
        val parts = ip.split(".")
        if (parts.size != 4) {
            println("$ip: invalid IP"); continue
        }
        val target = parts.fold(0L) { acc, p ->
            (acc shl 8) or p.toLong()
        }

        var found = false
        for (f in bl.feeds) {
            val idx = bisectRight(f.ipv4Starts, target) - 1
            if (idx >= 0 && target <= f.ipv4Ends[idx]) {
                val score = (f.baseScore / 200.0) *
                    (f.confidence / 200.0)
                val p = mutableListOf(f.name, "score=${"%.2f".format(score)}")
                val fl = bl.flags.filterIndexed { i, _ ->
                    f.flagsMask and (1u shl i) != 0u
                }
                if (fl.isNotEmpty()) p.add("flags=${fl.joinToString(",")}")
                val ca = bl.categories.filterIndexed { i, _ ->
                    f.categoriesMask and (1 shl i) != 0
                }
                if (ca.isNotEmpty()) p.add("cats=${ca.joinToString(",")}")
                println("$ip: ${p.joinToString(" | ")}")
                found = true
            }
        }
        if (!found) println("$ip: no matches")
    }
}
