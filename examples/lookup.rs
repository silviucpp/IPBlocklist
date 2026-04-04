use std::env;
use std::fs;
use std::net::IpAddr;

fn read_varint(data: &[u8], pos: &mut usize) -> u128 {
    let mut result: u128 = 0;
    let mut shift = 0;
    loop {
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u128) << shift;
        if byte & 0x80 == 0 { return result; }
        shift += 7;
    }
}

fn read_string(data: &[u8], pos: &mut usize) -> String {
    let len = data[*pos] as usize;
    *pos += 1;
    let s = String::from_utf8_lossy(&data[*pos..*pos + len]).into();
    *pos += len;
    s
}

fn read_u8(data: &[u8], pos: &mut usize) -> u8 {
    let v = data[*pos];
    *pos += 1;
    v
}

fn read_u16(data: &[u8], pos: &mut usize) -> u16 {
    let v = u16::from_le_bytes(data[*pos..*pos + 2].try_into().unwrap());
    *pos += 2;
    v
}

fn read_u32(data: &[u8], pos: &mut usize) -> u32 {
    let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    v
}

struct Feed {
    name: String,
    base_score: u8,
    confidence: u8,
    flags_mask: u32,
    categories_mask: u8,
    ipv4_starts: Vec<u64>,
    ipv4_ends: Vec<u64>,
    ipv6_starts: Vec<u128>,
    ipv6_ends: Vec<u128>,
}

struct Blocklist {
    flags: Vec<String>,
    categories: Vec<String>,
    feeds: Vec<Feed>,
}

fn load(path: &str) -> Blocklist {
    let data = fs::read(path).expect("cannot read file");
    let mut pos = 0;

    assert_eq!(&data[pos..pos + 4], b"IPBL");
    pos += 4;
    assert_eq!(read_u8(&data, &mut pos), 2);
    let _timestamp = read_u32(&data, &mut pos);

    let flag_count = read_u8(&data, &mut pos) as usize;
    let flags: Vec<String> =
        (0..flag_count).map(|_| read_string(&data, &mut pos)).collect();

    let cat_count = read_u8(&data, &mut pos) as usize;
    let categories: Vec<String> =
        (0..cat_count).map(|_| read_string(&data, &mut pos)).collect();

    let feed_count = read_u16(&data, &mut pos) as usize;
    let mut feeds = Vec::with_capacity(feed_count);

    for _ in 0..feed_count {
        let name = read_string(&data, &mut pos);
        let base_score = read_u8(&data, &mut pos);
        let confidence = read_u8(&data, &mut pos);
        let flags_mask = read_u32(&data, &mut pos);
        let categories_mask = read_u8(&data, &mut pos);
        let range_count = read_u32(&data, &mut pos) as usize;

        let mut v4s = Vec::new();
        let mut v4e = Vec::new();
        let mut v6s = Vec::new();
        let mut v6e = Vec::new();
        let mut current: u128 = 0;

        for _ in 0..range_count {
            current += read_varint(&data, &mut pos);
            let size = read_varint(&data, &mut pos);
            let end = current + size;
            if end <= 0xFFFF_FFFF {
                v4s.push(current as u64);
                v4e.push(end as u64);
            } else {
                v6s.push(current);
                v6e.push(end);
            }
        }

        feeds.push(Feed {
            name, base_score, confidence, flags_mask, categories_mask,
            ipv4_starts: v4s, ipv4_ends: v4e,
            ipv6_starts: v6s, ipv6_ends: v6e,
        });
    }

    Blocklist { flags, categories, feeds }
}

fn bisect_right(arr: &[u64], target: u64) -> usize {
    arr.partition_point(|&x| x <= target)
}

fn bisect_right_128(arr: &[u128], target: u128) -> usize {
    arr.partition_point(|&x| x <= target)
}

fn format_match(bl: &Blocklist, feed: &Feed) -> String {
    let score = (feed.base_score as f64 / 200.0)
              * (feed.confidence as f64 / 200.0);
    let mut parts = vec![feed.name.clone(), format!("score={score:.2}")];

    let matched_flags: Vec<&str> = bl.flags.iter().enumerate()
        .filter(|(i, _)| feed.flags_mask & (1 << i) != 0)
        .map(|(_, f)| f.as_str()).collect();
    if !matched_flags.is_empty() {
        parts.push(format!("flags={}", matched_flags.join(",")));
    }

    let matched_cats: Vec<&str> = bl.categories.iter().enumerate()
        .filter(|(i, _)| feed.categories_mask & (1 << i) != 0)
        .map(|(_, c)| c.as_str()).collect();
    if !matched_cats.is_empty() {
        parts.push(format!("cats={}", matched_cats.join(",")));
    }

    parts.join(" | ")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <ip> [<ip> ...]", args[0]);
        std::process::exit(1);
    }

    let bl = load("blocklist.bin");

    for ip_str in &args[1..] {
        let addr: IpAddr = match ip_str.parse() {
            Ok(a) => a,
            Err(_) => { println!("{ip_str}: invalid IP"); continue; }
        };

        let mut found = false;
        match addr {
            IpAddr::V4(v4) => {
                let target = u32::from(v4) as u64;
                for feed in &bl.feeds {
                    let idx = bisect_right(&feed.ipv4_starts, target);
                    if idx > 0 && target <= feed.ipv4_ends[idx - 1] {
                        println!(
                            "{ip_str}: {}", format_match(&bl, feed)
                        );
                        found = true;
                    }
                }
            }
            IpAddr::V6(v6) => {
                let target = u128::from(v6);
                for feed in &bl.feeds {
                    let idx = bisect_right_128(
                        &feed.ipv6_starts, target
                    );
                    if idx > 0 && target <= feed.ipv6_ends[idx - 1] {
                        println!(
                            "{ip_str}: {}", format_match(&bl, feed)
                        );
                        found = true;
                    }
                }
            }
        }
        if !found { println!("{ip_str}: no matches"); }
    }
}
