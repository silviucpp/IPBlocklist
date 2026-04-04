package main

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
)

type Feed struct {
	Name           string
	BaseScore      uint8
	Confidence     uint8
	FlagsMask      uint32
	CategoriesMask uint8
	IPv4Starts     []uint64
	IPv4Ends       []uint64
	IPv6Starts     []*big.Int
	IPv6Ends       []*big.Int
}

type Blocklist struct {
	Timestamp  uint32
	Flags      []string
	Categories []string
	Feeds      []Feed
}

func readVarint(data []byte, pos *int) *big.Int {
	result := new(big.Int)
	shift := uint(0)
	for {
		b := data[*pos]
		*pos++
		part := new(big.Int).SetUint64(uint64(b & 0x7F))
		part.Lsh(part, shift)
		result.Or(result, part)
		if b&0x80 == 0 {
			return result
		}
		shift += 7
	}
}

func readString(data []byte, pos *int) string {
	length := int(data[*pos])
	*pos++
	s := string(data[*pos : *pos+length])
	*pos += length
	return s
}

var maxIPv4 = new(big.Int).SetUint64(0xFFFFFFFF)

func Load(path string) (*Blocklist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pos := 0
	if string(data[pos:pos+4]) != "IPBL" {
		return nil, fmt.Errorf("invalid magic")
	}
	pos += 4

	if data[pos] != 2 {
		return nil, fmt.Errorf("unsupported version")
	}
	pos++

	bl := &Blocklist{}
	bl.Timestamp = binary.LittleEndian.Uint32(data[pos:])
	pos += 4

	flagCount := int(data[pos])
	pos++
	for i := 0; i < flagCount; i++ {
		bl.Flags = append(bl.Flags, readString(data, &pos))
	}

	catCount := int(data[pos])
	pos++
	for i := 0; i < catCount; i++ {
		bl.Categories = append(bl.Categories, readString(data, &pos))
	}

	feedCount := int(binary.LittleEndian.Uint16(data[pos:]))
	pos += 2

	for i := 0; i < feedCount; i++ {
		feed := Feed{Name: readString(data, &pos)}
		feed.BaseScore = data[pos]
		pos++
		feed.Confidence = data[pos]
		pos++
		feed.FlagsMask = binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		feed.CategoriesMask = data[pos]
		pos++

		rangeCount := binary.LittleEndian.Uint32(data[pos:])
		pos += 4

		current := new(big.Int)
		for r := uint32(0); r < rangeCount; r++ {
			delta := readVarint(data, &pos)
			size := readVarint(data, &pos)
			current.Add(current, delta)
			end := new(big.Int).Add(current, size)

			if end.Cmp(maxIPv4) <= 0 {
				feed.IPv4Starts = append(
					feed.IPv4Starts, current.Uint64(),
				)
				feed.IPv4Ends = append(
					feed.IPv4Ends, end.Uint64(),
				)
			} else {
				feed.IPv6Starts = append(
					feed.IPv6Starts, new(big.Int).Set(current),
				)
				feed.IPv6Ends = append(
					feed.IPv6Ends, new(big.Int).Set(end),
				)
			}
		}
		bl.Feeds = append(bl.Feeds, feed)
	}

	return bl, nil
}

func formatMatch(bl *Blocklist, f *Feed) string {
	score := float64(f.BaseScore) / 200.0 *
		float64(f.Confidence) / 200.0
	parts := []string{f.Name, fmt.Sprintf("score=%.2f", score)}

	var flags []string
	for i, name := range bl.Flags {
		if f.FlagsMask&(1<<uint(i)) != 0 {
			flags = append(flags, name)
		}
	}
	if len(flags) > 0 {
		parts = append(parts, "flags="+strings.Join(flags, ","))
	}

	var cats []string
	for i, name := range bl.Categories {
		if f.CategoriesMask&(1<<uint(i)) != 0 {
			cats = append(cats, name)
		}
	}
	if len(cats) > 0 {
		parts = append(parts, "cats="+strings.Join(cats, ","))
	}

	return strings.Join(parts, " | ")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ip> [<ip> ...]\n", os.Args[0])
		os.Exit(1)
	}

	bl, err := Load("blocklist.bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	for _, arg := range os.Args[1:] {
		ip := net.ParseIP(arg)
		if ip == nil {
			fmt.Printf("%s: invalid IP\n", arg)
			continue
		}

		found := false
		if v4 := ip.To4(); v4 != nil {
			target := uint64(v4[0])<<24 | uint64(v4[1])<<16 |
				uint64(v4[2])<<8 | uint64(v4[3])
			for i := range bl.Feeds {
				f := &bl.Feeds[i]
				idx := sort.Search(
					len(f.IPv4Starts),
					func(j int) bool {
						return f.IPv4Starts[j] > target
					},
				) - 1
				if idx >= 0 && target <= f.IPv4Ends[idx] {
					fmt.Printf("%s: %s\n", arg, formatMatch(bl, f))
					found = true
				}
			}
		} else {
			target := new(big.Int).SetBytes(ip.To16())
			for i := range bl.Feeds {
				f := &bl.Feeds[i]
				idx := sort.Search(
					len(f.IPv6Starts),
					func(j int) bool {
						return f.IPv6Starts[j].Cmp(target) > 0
					},
				) - 1
				if idx >= 0 && target.Cmp(f.IPv6Ends[idx]) <= 0 {
					fmt.Printf("%s: %s\n", arg, formatMatch(bl, f))
					found = true
				}
			}
		}

		if !found {
			fmt.Printf("%s: no matches\n", arg)
		}
	}
}
