package modbus

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"time"
)

// nowFunc is a package var (not time.Now called directly) so tests can
// inject a fake clock and assert drift deterministically instead of
// sleeping for real -- the same pattern s7comm/state.go and icsprobe's
// readDeadline use.
var nowFunc = time.Now

// driftWord synthesizes a plausible register value for an address nobody
// has written to, moving smoothly over time. This is the exact rationale
// s7comm/state.go's driftValue documents at length: a frozen value is a
// static-memory tell, and a per-second random redraw is white noise -- real
// analog process data (a level, temperature, or pressure register) is
// autocorrelated, moving a little between adjacent samples and a lot over
// minutes. The hash below only derives each address's fixed parameters
// (phase/period/centre/swing); the value itself is a slow sinusoid in time,
// so it is deterministic for a given (address, instant) pair yet never
// frozen or uniformly redrawn.
func driftWord(addr uint16) uint16 {
	t := float64(nowFunc().Unix())

	var seed [2]byte
	binary.BigEndian.PutUint16(seed[:], addr)
	sum := sha256.Sum256(seed[:])

	phase := float64(binary.BigEndian.Uint16(sum[0:2])) / 65535.0 * 2 * math.Pi
	// Periods of roughly 45s-300s, matching s7comm's driftValue: slow enough
	// that consecutive reads differ only slightly, fast enough to move
	// visibly over the course of a scan.
	period := 45.0 + float64(binary.BigEndian.Uint16(sum[2:4]))/65535.0*255.0
	// Centre and swing kept inside a plausible mid-range, never pinned to
	// the 0x0000/0xFFFF extremes a broken or unset simulation produces.
	centre := 12000.0 + float64(binary.BigEndian.Uint16(sum[4:6]))/65535.0*8000.0
	swing := 400.0 + float64(sum[6])/255.0*1200.0

	v := centre + swing*math.Sin(2*math.Pi*t/period+phase)
	return uint16(v)
}

// driftBit synthesizes a plausible discrete state for an address nobody has
// written to.
//
// DESIGN CHOICE, deliberately different from driftWord: this is time-
// invariant, not animated. Binary process points on a real PLC -- limit
// switches, run/fault contacts, alarm bits -- sit at one state for long
// stretches and change on a genuine event, not on a clock; unlike an analog
// register, a constant boolean is NOT itself a static-memory tell. What
// WOULD be a tell is every address reading the same value regardless of
// which one was asked for, so this is still keyed on the address (via the
// same hash-derived-parameters shape driftWord uses), just not on time.
func driftBit(addr uint16) bool {
	var seed [2]byte
	binary.BigEndian.PutUint16(seed[:], addr)
	sum := sha256.Sum256(seed[:])
	return sum[0]&1 == 1
}
