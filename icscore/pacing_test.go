package icscore

import (
	"sync"
	"testing"
	"time"
)

// freezeJitter makes Delay deterministic by pinning the random component,
// and restores the real one afterwards.
func freezeJitter(t *testing.T, value int64) {
	t.Helper()
	orig := jitterFunc
	jitterFunc = func(int64) int64 { return value }
	t.Cleanup(func() { jitterFunc = orig })
}

// captureSleep replaces the real sleep so tests never actually block, and
// records what was asked for.
func captureSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	orig := sleepFunc
	var mu sync.Mutex
	got := []time.Duration{}
	sleepFunc = func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, d)
	}
	t.Cleanup(func() { sleepFunc = orig })
	return &got
}

// The whole point of this type: a response must never be instant, because
// flat sub-millisecond timing is the fingerprint being removed.
func TestDelayNeverFallsBelowTheFloor(t *testing.T) {
	freezeJitter(t, 0)
	var p Pacer
	release := p.Enter()
	defer release()

	if got := p.Delay(); got < pacingFloor {
		t.Errorf("delay = %v, want >= floor %v", got, pacingFloor)
	}
}

// A constant delay is as synthetic as no delay. Pin that the jitter actually
// reaches the response, rather than being computed and discarded.
func TestDelayIncludesJitter(t *testing.T) {
	var p Pacer
	release := p.Enter()
	defer release()

	freezeJitter(t, 0)
	low := p.Delay()
	freezeJitter(t, int64(pacingJitter)-1)
	high := p.Delay()

	if high <= low {
		t.Errorf("jitter did not widen the delay: low=%v high=%v", low, high)
	}
	if low != pacingFloor {
		t.Errorf("zero jitter should give exactly the floor, got %v", low)
	}
}

// A single client on an idle device must not be charged a concurrency
// penalty -- otherwise the common case is slower than the model intends.
func TestSingleSessionPaysNoConcurrencyPenalty(t *testing.T) {
	freezeJitter(t, 0)
	var p Pacer
	release := p.Enter()
	defer release()

	if got := p.Delay(); got != pacingFloor {
		t.Errorf("delay = %v, want exactly the floor %v for one session", got, pacingFloor)
	}
}

// Communication jobs compete for the scan cycle, so more concurrent sessions
// must measurably slow every one of them.
func TestDelayGrowsWithConcurrency(t *testing.T) {
	freezeJitter(t, 0)
	var p Pacer

	r1 := p.Enter()
	defer r1()
	alone := p.Delay()

	r2 := p.Enter()
	defer r2()
	r3 := p.Enter()
	defer r3()
	crowded := p.Delay()

	if crowded <= alone {
		t.Errorf("delay did not grow with load: alone=%v crowded=%v", alone, crowded)
	}
	want := pacingFloor + 2*pacingPerConcurrent
	if crowded != want {
		t.Errorf("delay = %v, want %v (floor + 2 competing sessions)", crowded, want)
	}
}

// A connection flood must not turn the honeypot into a tarpit holding sockets
// open, which would stop it collecting -- the opposite of its purpose.
func TestDelayIsBounded(t *testing.T) {
	freezeJitter(t, int64(pacingJitter)-1)
	var p Pacer
	releases := make([]func(), 0, 500)
	for i := 0; i < 500; i++ {
		releases = append(releases, p.Enter())
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()

	if got := p.Delay(); got != pacingCeiling {
		t.Errorf("delay = %v, want it clamped to the ceiling %v", got, pacingCeiling)
	}
}

func TestPaceSleepsForTheComputedDelay(t *testing.T) {
	freezeJitter(t, 0)
	slept := captureSleep(t)
	var p Pacer
	release := p.Enter()
	defer release()

	p.Pace()

	if len(*slept) != 1 || (*slept)[0] != pacingFloor {
		t.Errorf("slept = %v, want exactly one sleep of %v", *slept, pacingFloor)
	}
}

// The gauge is load-bearing for the connection cap that will reuse it, so a
// double release must not make the device look idle while sessions run.
func TestReleaseIsIdempotent(t *testing.T) {
	var p Pacer
	release := p.Enter()
	release()
	release()

	if got := p.Active(); got != 0 {
		t.Errorf("active = %d, want 0 -- a double release must not drop below zero", got)
	}
}

func TestEnterAndReleaseAreConcurrencySafe(t *testing.T) {
	var p Pacer
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := p.Enter()
			_ = p.Delay()
			release()
		}()
	}
	wg.Wait()

	if got := p.Active(); got != 0 {
		t.Errorf("active = %d after all sessions released, want 0", got)
	}
}

// AtCapacity excludes the caller's own session, so a device whose limit is 1
// still serves the single client talking to it.
func TestAtCapacityExcludesTheCallersOwnSession(t *testing.T) {
	var p Pacer
	release := p.Enter()
	defer release()

	if p.AtCapacity(1) {
		t.Error("a lone session must not be at a limit of 1 -- the caller must not count against itself")
	}

	r2 := p.Enter()
	defer r2()
	if !p.AtCapacity(1) {
		t.Error("a second concurrent session must reach a limit of 1")
	}
}

func TestAtCapacityIsFalseWellBelowTheLimit(t *testing.T) {
	var p Pacer
	releases := make([]func(), 0, 4)
	for i := 0; i < 4; i++ {
		releases = append(releases, p.Enter())
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()

	if p.AtCapacity(16) {
		t.Errorf("4 sessions must be well below a limit of 16, active=%d", p.Active())
	}
}
