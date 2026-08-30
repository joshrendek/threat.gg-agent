package s7comm

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// maxTrackedAttackers bounds the per-IP state map (threat_gg-4zzd.6): once
// full, the least-recently-touched attacker is evicted to make room for a
// new one, so a scan flood from many source IPs cannot grow this map
// without bound.
const maxTrackedAttackers = 2000

// nowFunc is a package var (not time.Now called directly) so tests can
// inject a fake clock and assert drift deterministically instead of
// sleeping for real -- the same pattern icsprobe uses for readDeadline.
var nowFunc = time.Now

type cpuMode int

const (
	modeRun cpuMode = iota
	modeStop
)

// addressKey identifies one S7 address. Reads and writes are matched on the
// (area, db, byte offset) triple; a read that only partially overlaps a
// previous write, or asks for a different length, still gets that write's
// bytes truncated/zero-padded -- exact-length matching isn't worth the extra
// complexity for a honeypot, and "you get back roughly what you wrote" is
// what an attacker is checking for.
type addressKey struct {
	area       byte
	db         uint16
	byteOffset uint32
}

// attackerState is everything this honeypot remembers about ONE attacker IP:
// what it has written, and whether it has stopped the "CPU". It is never
// shared across IPs -- see stateStore.get, which is the only way to obtain
// one.
type attackerState struct {
	mu     sync.Mutex
	mode   cpuMode
	writes map[addressKey][]byte
}

// write records a write to addr for this attacker only.
func (s *attackerState) write(addr addressKey, data []byte) {
	stored := make([]byte, len(data))
	copy(stored, data)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writes == nil {
		s.writes = make(map[addressKey][]byte)
	}
	s.writes[addr] = stored
}

// read returns n bytes for addr: this SAME attacker's previous write there
// (truncated or zero-padded to n), or -- if this attacker never wrote to
// addr -- a value from the drifting simulated process. It never returns the
// same bytes forever for an address nobody has touched; see driftValue.
func (s *attackerState) read(addr addressKey, n int) []byte {
	s.mu.Lock()
	written, ok := s.writes[addr]
	s.mu.Unlock()

	if !ok {
		return driftValue(addr, n)
	}
	out := make([]byte, n)
	copy(out, written)
	return out
}

func (s *attackerState) setMode(m cpuMode) {
	s.mu.Lock()
	s.mode = m
	s.mu.Unlock()
}

func (s *attackerState) getMode() cpuMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// driftValue simulates plausible process data for an address nobody has
// written to. Every byte is a keyed hash of (address, byte index, current
// second), folded into a fixed range that avoids the suspicious extremes
// (0x00/0xFF): a static, all-zero, or all-identical response across days is
// itself the tell that outs a honeypot's memory as fake, so this must change
// whenever nowFunc's second ticks over, for every address independently.
//
// DESIGN CHOICE, not a sourced fact: the value is a slow sinusoid per address,
// not a per-second random draw.
//
// An earlier implementation hashed (address, byte index, unix second) into a
// uniform byte. That changes every second, which passes a naive drift test, but
// it is WHITE NOISE -- successive samples are uncorrelated across the whole
// range. Real process data does not behave that way: a temperature, level or
// pressure register is autocorrelated, moving a little between samples and a lot
// over minutes. An attacker polling one register at 1 Hz and seeing values jump
// uniformly across the range every second learns more from that than from a
// frozen value -- frozen at least reads as an idle plant, whereas white noise
// reads as nothing physical at all.
//
// Determinism is not lost by making it smooth: nowFunc is injectable, so a test
// picks two instants far enough apart to guarantee movement (the existing drift
// test uses a 120-second gap).
//
// The hash is still used, but only to derive each address's fixed PARAMETERS --
// phase, period and centre. That keeps distinct addresses independent and
// stable, while the value each returns moves smoothly in time.
func driftValue(addr addressKey, n int) []byte {
	if n <= 0 {
		return nil
	}
	t := float64(nowFunc().Unix())

	out := make([]byte, n)
	// Generate one smooth 16-bit quantity per aligned 2-byte word rather than
	// an independent value per byte: a WORD/INT read should look like one
	// analog reading, not two unrelated bytes stuck together.
	for i := 0; i < n; i += 2 {
		word := addr.byteOffset + uint32(i)

		var seed [8]byte
		seed[0] = addr.area
		binary.BigEndian.PutUint16(seed[1:3], addr.db)
		binary.BigEndian.PutUint32(seed[3:7], word)
		sum := sha256.Sum256(seed[:])

		// Fixed per-address parameters.
		phase := float64(binary.BigEndian.Uint16(sum[0:2])) / 65535.0 * 2 * math.Pi
		// Periods of roughly 45s to 300s: slow enough that consecutive reads
		// differ only slightly, fast enough to move visibly over a scan.
		period := 45.0 + float64(binary.BigEndian.Uint16(sum[2:4]))/65535.0*255.0
		// Centre and swing kept inside a plausible mid-range, never pinned to
		// the 0x0000/0xFFFF extremes a broken or static simulation produces.
		centre := 12000.0 + float64(binary.BigEndian.Uint16(sum[4:6]))/65535.0*8000.0
		swing := 400.0 + float64(sum[6])/255.0*1200.0

		v := centre + swing*math.Sin(2*math.Pi*t/period+phase)
		u := uint16(v)

		out[i] = byte(u >> 8)
		if i+1 < n {
			out[i+1] = byte(u)
		}
	}
	return out
}

// stateStore is the process-wide, bounded, per-attacker-IP state map. There
// is exactly one instance (globalState); it exists so a write or a STOP from
// one attacker IP is never visible to another (threat_gg-4zzd.6) -- the
// bug this honeypot must not repeat is a previous honeypot's globally-shared
// mutable emulated state, which let any anonymous caller change what every
// later visitor saw.
type stateStore struct {
	mu    sync.Mutex
	lru   *list.List // front = most recently used
	items map[string]*list.Element
}

type stateEntry struct {
	ip    string
	state *attackerState
}

func newStateStore() *stateStore {
	return &stateStore{lru: list.New(), items: make(map[string]*list.Element)}
}

// get returns the attackerState for ip, creating one if this is a new
// attacker. If the store is at capacity, the least-recently-used attacker's
// state is evicted first -- see maxTrackedAttackers.
func (s *stateStore) get(ip string) *attackerState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.items[ip]; ok {
		s.lru.MoveToFront(el)
		return el.Value.(*stateEntry).state
	}

	if s.lru.Len() >= maxTrackedAttackers {
		oldest := s.lru.Back()
		if oldest != nil {
			s.lru.Remove(oldest)
			delete(s.items, oldest.Value.(*stateEntry).ip)
		}
	}

	st := &attackerState{}
	el := s.lru.PushFront(&stateEntry{ip: ip, state: st})
	s.items[ip] = el
	return st
}

// globalState is the single per-IP state map this whole package's PDU
// handlers read and write through.
var globalState = newStateStore()
