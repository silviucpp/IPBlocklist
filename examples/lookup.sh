#!/usr/bin/env bash
set -euo pipefail

die() { echo "$1" >&2; exit 1; }
[[ $# -ge 1 ]] || die "Usage: $0 <ip> [<ip> ...]"

FILE="${BLOCKLIST_PATH:-blocklist.bin}"
[[ -f "$FILE" ]] || die "File not found: $FILE"

DATA=$(xxd -p -c 0 "$FILE" | tr -d '\n')

hex_at() { echo "${DATA:$(($1*2)):$(($2*2))}"; }

le16() {
    local h=$(hex_at "$1" 2)
    printf "%d" "0x${h:2:2}${h:0:2}"
}

le32() {
    local h=$(hex_at "$1" 4)
    printf "%d" "0x${h:6:2}${h:4:2}${h:2:2}${h:0:2}"
}

POS=4
VER=$(printf "%d" "0x$(hex_at $POS 1)")
[[ $VER -eq 2 ]] || die "Unsupported version: $VER"
POS=$((POS + 1 + 4))

FC=$(printf "%d" "0x$(hex_at $POS 1)")
POS=$((POS + 1))
declare -a FLAGS
for ((i=0; i<FC; i++)); do
    SLEN=$(printf "%d" "0x$(hex_at $POS 1)")
    POS=$((POS + 1))
    FLAGS[$i]=$(echo -n "$(hex_at $POS $SLEN)" | xxd -r -p)
    POS=$((POS + SLEN))
done

CC=$(printf "%d" "0x$(hex_at $POS 1)")
POS=$((POS + 1))
declare -a CATS
for ((i=0; i<CC; i++)); do
    SLEN=$(printf "%d" "0x$(hex_at $POS 1)")
    POS=$((POS + 1))
    CATS[$i]=$(echo -n "$(hex_at $POS $SLEN)" | xxd -r -p)
    POS=$((POS + SLEN))
done

FEED_COUNT=$(le16 $POS)
POS=$((POS + 2))

declare -a FEED_NAMES FEED_BS FEED_CO FEED_FM FEED_CM
declare -a FEED_V4S FEED_V4E

for ((fi=0; fi<FEED_COUNT; fi++)); do
    NLEN=$(printf "%d" "0x$(hex_at $POS 1)")
    POS=$((POS + 1))
    FEED_NAMES[$fi]=$(echo -n "$(hex_at $POS $NLEN)" | xxd -r -p)
    POS=$((POS + NLEN))

    FEED_BS[$fi]=$(printf "%d" "0x$(hex_at $POS 1)")
    POS=$((POS + 1))
    FEED_CO[$fi]=$(printf "%d" "0x$(hex_at $POS 1)")
    POS=$((POS + 1))
    FEED_FM[$fi]=$(le32 $POS)
    POS=$((POS + 4))
    FEED_CM[$fi]=$(printf "%d" "0x$(hex_at $POS 1)")
    POS=$((POS + 1))

    RC=$(le32 $POS)
    POS=$((POS + 4))

    V4S="" V4E="" CUR=0
    for ((r=0; r<RC; r++)); do
        RESULT=0 SHIFT=0
        while true; do
            B=$(printf "%d" "0x$(hex_at $POS 1)")
            POS=$((POS + 1))
            RESULT=$(( RESULT | ((B & 127) << SHIFT) ))
            [[ $((B & 128)) -ne 0 ]] || break
            SHIFT=$((SHIFT + 7))
        done
        CUR=$((CUR + RESULT))

        RESULT=0 SHIFT=0
        while true; do
            B=$(printf "%d" "0x$(hex_at $POS 1)")
            POS=$((POS + 1))
            RESULT=$(( RESULT | ((B & 127) << SHIFT) ))
            [[ $((B & 128)) -ne 0 ]] || break
            SHIFT=$((SHIFT + 7))
        done
        END=$((CUR + RESULT))

        if [[ $END -le $((0xFFFFFFFF)) ]]; then
            V4S="$V4S $CUR"
            V4E="$V4E $END"
        fi
    done
    FEED_V4S[$fi]="$V4S"
    FEED_V4E[$fi]="$V4E"
done

ip_to_int() {
    IFS='.' read -r a b c d <<< "$1"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

for IP in "$@"; do
    if ! [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$IP: invalid/unsupported IP"; continue
    fi

    TARGET=$(ip_to_int "$IP")
    FOUND=0

    for ((fi=0; fi<FEED_COUNT; fi++)); do
        read -ra STARTS <<< "${FEED_V4S[$fi]}"
        read -ra ENDS <<< "${FEED_V4E[$fi]}"

        LO=0 HI=${#STARTS[@]}
        while [[ $LO -lt $HI ]]; do
            MID=$(( (LO + HI) / 2 ))
            if [[ ${STARTS[$MID]} -le $TARGET ]]; then
                LO=$((MID + 1))
            else
                HI=$MID
            fi
        done
        IDX=$((LO - 1))

        if [[ $IDX -ge 0 ]] && [[ $TARGET -le ${ENDS[$IDX]} ]]; then
            echo "$IP: ${FEED_NAMES[$fi]}"
            FOUND=1
        fi
    done

    [[ $FOUND -eq 1 ]] || echo "$IP: no matches"
done
