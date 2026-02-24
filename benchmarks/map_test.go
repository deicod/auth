package benchmarks

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

type StringKey struct {
	IP     string
	Action string
}

type PtrValue struct {
	Count   int
	ResetAt time.Time
}

type StructKey struct {
	IP     [16]byte
	Action uint64
}

type NoPtrValue struct {
	Count   int
	ResetAt int64
}

var (
	stringMap = make(map[StringKey]PtrValue)
	structMap = make(map[StructKey]NoPtrValue)
)

func init() {
	for i := 0; i < 10000; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i%255)
		stringMap[StringKey{IP: ip, Action: "login"}] = PtrValue{Count: 1, ResetAt: time.Now()}

		addr, _ := netip.ParseAddr(ip)
		structMap[StructKey{IP: addr.As16(), Action: 1}] = NoPtrValue{Count: 1, ResetAt: time.Now().UnixNano()}
	}
}

func BenchmarkMapStringKey(b *testing.B) {
	key := StringKey{IP: "192.168.1.1", Action: "login"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := stringMap[key]; ok {
			_ = ok
		}
	}
}

func BenchmarkMapStructKey(b *testing.B) {
	addr, _ := netip.ParseAddr("192.168.1.1")
	key := StructKey{IP: addr.As16(), Action: 1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := structMap[key]; ok {
			_ = ok
		}
	}
}
