import scala.io.Source
import java.io.{FileInputStream, DataInputStream, BufferedInputStream}
import java.net.InetAddress

object Lookup {
  case class Feed(
    name: String, baseScore: Int, confidence: Int,
    flagsMask: Long, categoriesMask: Int,
    ipv4Starts: Array[Long], ipv4Ends: Array[Long],
    flags: Seq[String], categories: Seq[String]
  )

  class Reader(data: Array[Byte]) {
    var pos = 0

    def u8(): Int = { val v = data(pos) & 0xFF; pos += 1; v }

    def u16(): Int = {
      val v = (data(pos) & 0xFF) | ((data(pos+1) & 0xFF) << 8)
      pos += 2; v
    }

    def u32(): Long = {
      val v = (data(pos).toLong & 0xFF) |
        ((data(pos+1).toLong & 0xFF) << 8) |
        ((data(pos+2).toLong & 0xFF) << 16) |
        ((data(pos+3).toLong & 0xFF) << 24)
      pos += 4; v
    }

    def str(): String = {
      val len = u8()
      val s = new String(data, pos, len)
      pos += len; s
    }

    def varint(): Long = {
      var result = 0L; var shift = 0
      while (true) {
        val b = u8()
        result |= (b.toLong & 0x7F) << shift
        if ((b & 0x80) == 0) return result
        shift += 7
      }
      result
    }
  }

  def load(path: String = "blocklist.bin"): Seq[Feed] = {
    val data = java.nio.file.Files.readAllBytes(
      java.nio.file.Path.of(path)
    )
    val r = new Reader(data)
    r.pos = 4
    assert(r.u8() == 2)
    r.u32() // timestamp

    val flags = (0 until r.u8()).map(_ => r.str())
    val cats = (0 until r.u8()).map(_ => r.str())
    val feedCount = r.u16()

    (0 until feedCount).map { _ =>
      val name = r.str()
      val bs = r.u8(); val co = r.u8()
      val fm = r.u32(); val cm = r.u8()
      val rc = r.u32().toInt

      val v4s = collection.mutable.ArrayBuffer[Long]()
      val v4e = collection.mutable.ArrayBuffer[Long]()
      var current = 0L

      (0 until rc).foreach { _ =>
        current += r.varint()
        val size = r.varint()
        val end = current + size
        if (end <= 0xFFFFFFFFL) {
          v4s += current; v4e += end
        }
      }

      val mf = flags.zipWithIndex.collect {
        case (f, i) if (fm & (1L << i)) != 0 => f
      }
      val mc = cats.zipWithIndex.collect {
        case (c, i) if (cm & (1 << i)) != 0 => c
      }

      Feed(name, bs, co, fm, cm, v4s.toArray, v4e.toArray, mf, mc)
    }
  }

  def bisectRight(arr: Array[Long], target: Long): Int = {
    var lo = 0; var hi = arr.length
    while (lo < hi) {
      val mid = lo + (hi - lo) / 2
      if (arr(mid) <= target) lo = mid + 1 else hi = mid
    }
    lo
  }

  def main(args: Array[String]): Unit = {
    if (args.isEmpty) {
      System.err.println("Usage: scala Lookup <ip> [<ip> ...]")
      return
    }

    val feeds = load()

    args.foreach { ip =>
      val parts = ip.split('.')
      if (parts.length != 4) {
        println(s"$ip: invalid IP"); return
      }

      val target = parts.foldLeft(0L) { (acc, p) =>
        (acc << 8) | p.toLong
      }

      var found = false
      feeds.foreach { f =>
        val idx = bisectRight(f.ipv4Starts, target) - 1
        if (idx >= 0 && target <= f.ipv4Ends(idx)) {
          val score = (f.baseScore / 200.0) * (f.confidence / 200.0)
          val p = collection.mutable.ArrayBuffer(
            f.name, f"score=$score%.2f"
          )
          if (f.flags.nonEmpty)
            p += s"flags=${f.flags.mkString(",")}"
          if (f.categories.nonEmpty)
            p += s"cats=${f.categories.mkString(",")}"
          println(s"$ip: ${p.mkString(" | ")}")
          found = true
        }
      }
      if (!found) println(s"$ip: no matches")
    }
  }
}
