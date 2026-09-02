package icscore

import (
	"math/rand"
	"sync/atomic"
	"time"
)

// A real PLC CPU does not answer instantly and does not answer at a constant
// speed. Communication is a job scheduled against the scan cycle, so replies
// land in milliseconds with genuine jitter, and they get measurably slower as
// more clients talk to the CPU at once. A Go handler answers in microseconds,
// flat, forever -- and flat sub-millisecond timing is one of the cheapest
// honeypot fingerprints there is, measurable by any client with a clock and
// costing an attacker nothing to check (threat_gg-4zzd.9).
//
// EVERY NUMBER BELOW IS INVENTED, in the sense 4zzd.3 requires them to be
// marked: we have no reference hardware to time, so these are plausible
// magnitudes for a small PLC rather than measurements of one. They are worth
// shipping anyway, and that is a different judgement from the one that makes
// us DECLINE to answer an unsupported SZL index. Declining is right when a
// wrong answer would be checkable against a public registry and silence is
// ordinary device behaviour. Here there is no silence available: we already
// emit a timing signature on every response, and the one we emit today --
// perfectly flat, microseconds -- is certainly wrong. Any plausible model is
// strictly closer to real than that, the same reasoning that justified
// pinning IP TTL to 60 rather than leaving it at Linux's 64.
const (
	// pacingFloor is the fastest we will ever answer.
	pacingFloor = 6 * time.Millisecond
	// pacingJitter is the width of the random spread added to the floor, so
	// replies land in roughly 6-18ms when the device is otherwise idle.
	// The spread matters more than the midpoint: a constant 12ms is as
	// obviously synthetic as a constant 12us.
	pacingJitter = 12 * time.Millisecond
	// pacingPerConcurrent is added for each OTHER session in flight,
	// modelling communication jobs competing for the same scan cycle.
	pacingPerConcurrent = 2 * time.Millisecond
	// pacingCeiling bounds the total so a connection flood cannot turn the
	// honeypot into a tarpit that holds sockets open and stops collecting.
	pacingCeiling = 250 * time.Millisecond
)

// sleepFunc and jitterFunc are package vars so tests can make pacing
// deterministic and instant instead of sleeping for real -- the same
// injection pattern as modbus's nowFunc and icsprobe's readDeadline.
var (
	sleepFunc  = time.Sleep
	jitterFunc = func(n int64) int64 { return rand.Int63n(n) }
)

// Pacer models a CPU's response latency across all of its concurrent
// sessions. The zero value is ready to use, and it is safe for concurrent
// use by every connection goroutine.
//
// It also carries the count of in-flight sessions, which is the same figure a
// connection cap needs (the second half of 4zzd.9): a real CPU supports only
// a small fixed number of concurrent PG/OP connections, and a listener that
// cheerfully accepts hundreds is its own tell. The gauge is kept here so that
// change reuses it rather than counting sessions twice.
type Pacer struct {
	active atomic.Int64
}

// Enter registers a session as in flight and returns the function that
// releases it. Callers should `defer` the returned function immediately:
//
//	release := pacer.Enter()
//	defer release()
func (p *Pacer) Enter() func() {
	p.active.Add(1)
	var once atomic.Bool
	return func() {
		// Guard against a double release dropping the gauge below zero and
		// making the device look idle while sessions are still running.
		if once.CompareAndSwap(false, true) {
			p.active.Add(-1)
		}
	}
}

// Active reports how many sessions are currently in flight.
func (p *Pacer) Active() int { return int(p.active.Load()) }

// Delay computes one response's latency: a jittered floor, plus a penalty for
// every OTHER session competing for the CPU, bounded by pacingCeiling.
func (p *Pacer) Delay() time.Duration {
	d := pacingFloor + time.Duration(jitterFunc(int64(pacingJitter)))

	// Subtract this session, so a single caller on an idle device pays no
	// concurrency penalty at all.
	if others := p.Active() - 1; others > 0 {
		d += time.Duration(others) * pacingPerConcurrent
	}
	if d > pacingCeiling {
		d = pacingCeiling
	}
	return d
}

// Pace blocks for one response's worth of latency. Call it immediately before
// writing a response, never after: the delay has to sit between the request
// and the reply to be the thing a client measures.
func (p *Pacer) Pace() { sleepFunc(p.Delay()) }

// AtCapacity reports whether this device already has as many sessions in
// flight as it is willing to serve, EXCLUDING the caller's own session.
//
// Real CPUs support a small fixed number of concurrent PG/OP connections --
// single digits to low double digits -- and a listener that cheerfully
// accepts hundreds is a tell that costs an attacker nothing to check
// (threat_gg-4zzd.9). limit is supplied by the calling protocol because the
// plausible figure differs per device, and because icscore should not be the
// place a device's identity is decided.
//
// Callers must still ACCEPT and RECORD the connection: refusing at the TCP
// layer would lose the capture, which is the one thing this system must not
// do. Answer with the protocol's own "busy" instead.
func (p *Pacer) AtCapacity(limit int) bool {
	return p.Active()-1 >= limit
}
