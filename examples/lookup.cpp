#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <arpa/inet.h>

struct Feed {
    std::string name;
    uint8_t base_score, confidence;
    uint32_t flags_mask;
    uint8_t categories_mask;
    std::vector<uint64_t> ipv4_starts, ipv4_ends;
};

struct Blocklist {
    std::vector<std::string> flags, categories;
    std::vector<Feed> feeds;
};

class Reader {
    const uint8_t *data;
    size_t pos = 0;
public:
    Reader(const uint8_t *d) : data(d) {}

    uint8_t u8() { return data[pos++]; }

    uint16_t u16() {
        uint16_t v;
        memcpy(&v, data + pos, 2); pos += 2;
        return v;
    }

    uint32_t u32() {
        uint32_t v;
        memcpy(&v, data + pos, 4); pos += 4;
        return v;
    }

    std::string str() {
        auto len = u8();
        std::string s(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        return s;
    }

    uint64_t varint() {
        uint64_t result = 0;
        int shift = 0;
        while (true) {
            auto b = u8();
            result |= uint64_t(b & 0x7F) << shift;
            if (!(b & 0x80)) return result;
            shift += 7;
        }
    }

    void skip(size_t n) { pos += n; }
};

Blocklist load(const char *path = "blocklist.bin") {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    auto size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> buf(size);
    file.read(reinterpret_cast<char*>(buf.data()), size);

    Reader r(buf.data());
    r.skip(4); // IPBL
    r.u8();    // version
    r.u32();   // timestamp

    Blocklist bl;
    auto fc = r.u8();
    for (int i = 0; i < fc; i++) bl.flags.push_back(r.str());
    auto cc = r.u8();
    for (int i = 0; i < cc; i++) bl.categories.push_back(r.str());

    auto feed_count = r.u16();
    for (int i = 0; i < feed_count; i++) {
        Feed f;
        f.name = r.str();
        f.base_score = r.u8();
        f.confidence = r.u8();
        f.flags_mask = r.u32();
        f.categories_mask = r.u8();
        auto rc = r.u32();
        uint64_t current = 0;
        for (uint32_t j = 0; j < rc; j++) {
            current += r.varint();
            auto sz = r.varint();
            auto end = current + sz;
            if (end <= 0xFFFFFFFFULL) {
                f.ipv4_starts.push_back(current);
                f.ipv4_ends.push_back(end);
            }
        }
        bl.feeds.push_back(std::move(f));
    }
    return bl;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ip> [<ip> ...]\n", argv[0]);
        return 1;
    }

    auto bl = load();

    for (int a = 1; a < argc; a++) {
        in_addr addr;
        if (inet_pton(AF_INET, argv[a], &addr) != 1) {
            printf("%s: invalid/unsupported IP\n", argv[a]);
            continue;
        }

        auto target = uint64_t(ntohl(addr.s_addr));
        bool found = false;

        for (auto &f : bl.feeds) {
            auto it = std::upper_bound(
                f.ipv4_starts.begin(), f.ipv4_starts.end(), target
            );
            if (it != f.ipv4_starts.begin()) {
                auto idx = std::distance(
                    f.ipv4_starts.begin(), it
                ) - 1;
                if (target <= f.ipv4_ends[idx]) {
                    double score = (f.base_score / 200.0)
                                 * (f.confidence / 200.0);
                    printf("%s: %s | score=%.2f",
                        argv[a], f.name.c_str(), score);

                    bool first = true;
                    for (size_t i = 0; i < bl.flags.size(); i++)
                        if (f.flags_mask & (1u << i)) {
                            printf("%s%s",
                                first ? " | flags=" : ",",
                                bl.flags[i].c_str());
                            first = false;
                        }

                    first = true;
                    for (size_t i = 0; i < bl.categories.size(); i++)
                        if (f.categories_mask & (1u << i)) {
                            printf("%s%s",
                                first ? " | cats=" : ",",
                                bl.categories[i].c_str());
                            first = false;
                        }
                    printf("\n");
                    found = true;
                }
            }
        }

        if (!found) printf("%s: no matches\n", argv[a]);
    }
    return 0;
}
