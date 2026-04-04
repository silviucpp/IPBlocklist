#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned __int128 uint128_t;

typedef struct {
    char name[256];
    uint8_t base_score;
    uint8_t confidence;
    uint32_t flags_mask;
    uint8_t categories_mask;
    uint32_t ipv4_count;
    uint64_t *ipv4_starts;
    uint64_t *ipv4_ends;
    uint32_t ipv6_count;
    uint128_t *ipv6_starts;
    uint128_t *ipv6_ends;
} Feed;

typedef struct {
    uint32_t timestamp;
    uint8_t flag_count;
    char flags[64][256];
    uint8_t cat_count;
    char categories[32][256];
    uint16_t feed_count;
    Feed *feeds;
} Blocklist;

static uint64_t read_varint(FILE *f) {
    uint64_t result = 0;
    int shift = 0;
    while (1) {
        int byte = fgetc(f);
        if (byte == EOF) return 0;
        result |= (uint64_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) return result;
        shift += 7;
    }
}

static void read_string(FILE *f, char *buf) {
    uint8_t length;
    fread(&length, 1, 1, f);
    fread(buf, 1, length, f);
    buf[length] = '\0';
}

static int load_blocklist(const char *path, Blocklist *bl) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    char magic[4];
    fread(magic, 1, 4, f);
    if (memcmp(magic, "IPBL", 4) != 0) { fclose(f); return -1; }

    uint8_t version;
    fread(&version, 1, 1, f);
    if (version != 2) { fclose(f); return -1; }

    fread(&bl->timestamp, 4, 1, f);
    fread(&bl->flag_count, 1, 1, f);
    for (int i = 0; i < bl->flag_count; i++)
        read_string(f, bl->flags[i]);

    fread(&bl->cat_count, 1, 1, f);
    for (int i = 0; i < bl->cat_count; i++)
        read_string(f, bl->categories[i]);

    fread(&bl->feed_count, 2, 1, f);
    bl->feeds = calloc(bl->feed_count, sizeof(Feed));

    for (int i = 0; i < bl->feed_count; i++) {
        Feed *feed = &bl->feeds[i];
        read_string(f, feed->name);
        fread(&feed->base_score, 1, 1, f);
        fread(&feed->confidence, 1, 1, f);
        fread(&feed->flags_mask, 4, 1, f);
        fread(&feed->categories_mask, 1, 1, f);

        uint32_t range_count;
        fread(&range_count, 4, 1, f);

        uint64_t *starts = malloc(range_count * sizeof(uint64_t));
        uint64_t *ends = malloc(range_count * sizeof(uint64_t));
        uint128_t *starts6 = malloc(range_count * sizeof(uint128_t));
        uint128_t *ends6 = malloc(range_count * sizeof(uint128_t));
        uint32_t n4 = 0, n6 = 0;

        uint128_t current = 0;
        for (uint32_t r = 0; r < range_count; r++) {
            current += (uint128_t)read_varint(f);
            uint128_t size = (uint128_t)read_varint(f);
            uint128_t end = current + size;
            if (end <= 0xFFFFFFFFULL) {
                starts[n4] = (uint64_t)current;
                ends[n4] = (uint64_t)end;
                n4++;
            } else {
                starts6[n6] = current;
                ends6[n6] = end;
                n6++;
            }
        }

        feed->ipv4_count = n4;
        feed->ipv4_starts = realloc(starts, n4 * sizeof(uint64_t));
        feed->ipv4_ends = realloc(ends, n4 * sizeof(uint64_t));
        feed->ipv6_count = n6;
        feed->ipv6_starts = realloc(starts6, n6 * sizeof(uint128_t));
        feed->ipv6_ends = realloc(ends6, n6 * sizeof(uint128_t));
    }

    fclose(f);
    return 0;
}

static int bisect_right_u64(
    const uint64_t *arr, uint32_t len, uint64_t target
) {
    int lo = 0, hi = (int)len;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (arr[mid] <= target) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static int bisect_right_u128(
    const uint128_t *arr, uint32_t len, uint128_t target
) {
    int lo = 0, hi = (int)len;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (arr[mid] <= target) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static void print_match(const Blocklist *bl, const Feed *feed) {
    double score = (feed->base_score / 200.0)
                 * (feed->confidence / 200.0);
    printf("  %s | score=%.2f", feed->name, score);

    int first = 1;
    for (int i = 0; i < bl->flag_count; i++) {
        if (feed->flags_mask & (1U << i)) {
            printf("%s%s", first ? " | flags=" : ",", bl->flags[i]);
            first = 0;
        }
    }

    first = 1;
    for (int i = 0; i < bl->cat_count; i++) {
        if (feed->categories_mask & (1U << i)) {
            printf(
                "%s%s", first ? " | cats=" : ",", bl->categories[i]
            );
            first = 0;
        }
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ip> [<ip> ...]\n", argv[0]);
        return 1;
    }

    Blocklist bl;
    if (load_blocklist("blocklist.bin", &bl) != 0) {
        fprintf(stderr, "Failed to load blocklist.bin\n");
        return 1;
    }

    for (int a = 1; a < argc; a++) {
        struct in_addr addr4;
        struct in6_addr addr6;
        int found = 0;

        if (inet_pton(AF_INET, argv[a], &addr4) == 1) {
            uint64_t target = ntohl(addr4.s_addr);
            for (int i = 0; i < bl.feed_count; i++) {
                Feed *feed = &bl.feeds[i];
                int idx = bisect_right_u64(
                    feed->ipv4_starts, feed->ipv4_count, target
                ) - 1;
                if (idx >= 0 && target <= feed->ipv4_ends[idx]) {
                    if (!found) printf("%s:\n", argv[a]);
                    print_match(&bl, feed);
                    found = 1;
                }
            }
        } else if (inet_pton(AF_INET6, argv[a], &addr6) == 1) {
            uint128_t target = 0;
            for (int i = 0; i < 16; i++)
                target = (target << 8) | addr6.s6_addr[i];
            for (int i = 0; i < bl.feed_count; i++) {
                Feed *feed = &bl.feeds[i];
                int idx = bisect_right_u128(
                    feed->ipv6_starts, feed->ipv6_count, target
                ) - 1;
                if (idx >= 0 && target <= feed->ipv6_ends[idx]) {
                    if (!found) printf("%s:\n", argv[a]);
                    print_match(&bl, feed);
                    found = 1;
                }
            }
        } else {
            printf("%s: invalid IP\n", argv[a]);
            continue;
        }

        if (!found) printf("%s: no matches\n", argv[a]);
    }

    for (int i = 0; i < bl.feed_count; i++) {
        free(bl.feeds[i].ipv4_starts);
        free(bl.feeds[i].ipv4_ends);
        free(bl.feeds[i].ipv6_starts);
        free(bl.feeds[i].ipv6_ends);
    }
    free(bl.feeds);
    return 0;
}
