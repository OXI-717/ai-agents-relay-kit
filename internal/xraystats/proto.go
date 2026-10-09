package xraystats

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Minimal protobuf codec for the three xray StatsService messages we use.
// Wire types: 0 = varint, 2 = length-delimited.

func appendVarint(b []byte, v uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	return append(b, tmp[:n]...)
}

func appendTag(b []byte, field, wire int) []byte {
	return appendVarint(b, uint64(field<<3|wire))
}

func appendFieldString(b []byte, field int, s string) []byte {
	b = appendTag(b, field, 2)
	b = appendVarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendFieldBytes(b []byte, field int, m []byte) []byte {
	b = appendTag(b, field, 2)
	b = appendVarint(b, uint64(len(m)))
	return append(b, m...)
}

func appendFieldBool(b []byte, field int, v bool) []byte {
	b = appendTag(b, field, 0)
	if v {
		return append(b, 1)
	}
	return append(b, 0)
}

func appendFieldVarint(b []byte, field int, v uint64) []byte {
	b = appendTag(b, field, 0)
	return appendVarint(b, v)
}

// field is one decoded protobuf field.
type field struct {
	num    int
	wire   int
	varint uint64
	data   []byte
}

// parseFields decodes all fields of a message.
func parseFields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("bad field tag")
		}
		b = b[n:]
		f := field{num: int(tag >> 3), wire: int(tag & 7)}
		switch f.wire {
		case 0:
			v, m := binary.Uvarint(b)
			if m <= 0 {
				return nil, fmt.Errorf("bad varint field %d", f.num)
			}
			f.varint, b = v, b[m:]
		case 2:
			l, m := binary.Uvarint(b)
			if m <= 0 || m+int(l) > len(b) {
				return nil, fmt.Errorf("bad len field %d", f.num)
			}
			f.data, b = b[m:m+int(l)], b[m+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, io.ErrUnexpectedEOF
			}
			f.data, b = b[:4], b[4:]
		case 1:
			if len(b) < 8 {
				return nil, io.ErrUnexpectedEOF
			}
			f.data, b = b[:8], b[8:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out, nil
}

// gRPC frame: 1-byte compression flag + 4-byte big-endian length + message.
func frame(msg []byte) []byte {
	b := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	return append(b, msg...)
}

func unframe(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0 {
		return nil, fmt.Errorf("compressed gRPC frames unsupported")
	}
	msg := make([]byte, binary.BigEndian.Uint32(hdr[1:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// --- QueryStats ---

func encQueryStats(pattern string, reset bool) []byte {
	return frame(appendFieldBool(appendFieldString(nil, 1, pattern), 2, reset))
}

func decQueryStats(msg []byte) (map[string]int64, error) {
	fs, err := parseFields(msg)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, f := range fs {
		if f.num != 1 || f.wire != 2 {
			continue
		}
		st, err := parseFields(f.data)
		if err != nil {
			return nil, err
		}
		var name string
		var val int64
		for _, sf := range st {
			switch {
			case sf.num == 1 && sf.wire == 2:
				name = string(sf.data)
			case sf.num == 2 && sf.wire == 0:
				val = int64(sf.varint)
			}
		}
		out[name] = val
	}
	return out, nil
}

// --- SysStats ---

type SysStats struct {
	NumGoroutine uint32
	NumGC        uint32
	Alloc        uint64
	TotalAlloc   uint64
	Sys          uint64
	Mallocs      uint64
	Frees        uint64
	LiveObjects  uint64
	Uptime       uint32 // seconds since the xray process started
}

func decSysStats(msg []byte) (SysStats, error) {
	var s SysStats
	fs, err := parseFields(msg)
	if err != nil {
		return s, err
	}
	for _, f := range fs {
		if f.wire != 0 {
			continue
		}
		switch f.num {
		case 1:
			s.NumGoroutine = uint32(f.varint)
		case 2:
			s.NumGC = uint32(f.varint)
		case 3:
			s.Alloc = f.varint
		case 4:
			s.TotalAlloc = f.varint
		case 5:
			s.Sys = f.varint
		case 6:
			s.Mallocs = f.varint
		case 7:
			s.Frees = f.varint
		case 8:
			s.LiveObjects = f.varint
		case 9:
			s.Uptime = uint32(f.varint)
		}
	}
	return s, nil
}

// --- GetStatsOnlineIpList: response { map<string, IPList> ips = 1 } ---

func decOnlineIPs(msg []byte) (int, error) {
	fs, err := parseFields(msg)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range fs {
		if f.num != 1 || f.wire != 2 {
			continue
		}
		entry, err := parseFields(f.data)
		if err != nil {
			return 0, err
		}
		for _, e := range entry {
			if e.num != 2 || e.wire != 2 { // value: IPList
				continue
			}
			ips, err := parseFields(e.data)
			if err != nil {
				return 0, err
			}
			for _, ip := range ips {
				if ip.num == 1 {
					n++
				}
			}
		}
	}
	return n, nil
}
