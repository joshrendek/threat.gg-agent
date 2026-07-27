package llmcore

import (
	"encoding/json"
	"math/rand"
	"sync"
	"time"
)

// Timings are the nanosecond durations a real inference server reports alongside a completion.
// The previous implementation returned the same five constants on every request, so two
// requests from the same scanner produced byte-identical duration fields — a decisive tell.
// These are derived from the request's own token counts with jitter, and honour whether the
// model is already resident (see loadState).
type Timings struct {
	Total      time.Duration
	Load       time.Duration
	PromptEval time.Duration
	Eval       time.Duration
}

// Per-token costs and cold-start ranges, taken from a real Ollama 0.30.11 running a 7B Q4_K_M
// model: prompt eval ~3.5-7.2ms/token, generation ~17-18ms/token, cold load 1.5-4.8s, warm load
// single-digit-to-low-double-digit ms.
const (
	promptEvalPerTokenMin = 3200 * time.Microsecond
	promptEvalPerTokenMax = 7400 * time.Microsecond
	evalPerTokenMin       = 14 * time.Millisecond
	evalPerTokenMax       = 21 * time.Millisecond
	coldLoadMin           = 1400 * time.Millisecond
	coldLoadMax           = 4800 * time.Millisecond
	warmLoadMin           = 8 * time.Millisecond
	warmLoadMax           = 35 * time.Millisecond
	// defaultKeepAlive matches Ollama's own 5m default for how long a model stays resident.
	defaultKeepAlive = 5 * time.Minute
)

// loadState tracks which models are "resident", so a repeated request reports a warm load
// duration and a request after keep_alive expiry reports a cold one. A scanner that probes the
// same endpoint twice sees the second call get faster, exactly as a real server behaves.
type loadState struct {
	mu       sync.Mutex
	residing map[string]time.Time // model -> unload deadline
}

var models = &loadState{residing: map[string]time.Time{}}

// touch marks model resident for d and reports whether it was already resident beforehand.
// Zero unloads immediately; a negative duration keeps the model resident indefinitely.
func (s *loadState) touch(model string, d time.Duration) (wasWarm bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	deadline, ok := s.residing[model]
	wasWarm = ok && now.Before(deadline)
	if d == 0 {
		delete(s.residing, model)
		return wasWarm
	}
	if d < 0 {
		s.residing[model] = now.Add(time.Duration(1<<63 - 1))
		return wasWarm
	}
	s.residing[model] = now.Add(d)
	return wasWarm
}

// ResidentModels returns the models currently held "in memory" with their unload deadlines.
// Ollama's /api/ps reports exactly this, so an attacker who runs a completion and then checks
// /api/ps sees the model they just used listed as loaded — and sees it disappear later.
func ResidentModels() map[string]time.Time {
	models.mu.Lock()
	defer models.mu.Unlock()
	now := time.Now()
	out := map[string]time.Time{}
	for name, deadline := range models.residing {
		if now.Before(deadline) {
			out[name] = deadline
		} else {
			delete(models.residing, name)
		}
	}
	return out
}

func jitter(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

// keepAliveOf reads the request's "keep_alive" field. Ollama accepts a duration string ("10m")
// or a number of seconds; anything absent or unparseable means the 5m default.
func keepAliveOf(body []byte) time.Duration {
	var m struct {
		KeepAlive json.RawMessage `json:"keep_alive"`
	}
	if err := json.Unmarshal(body, &m); err != nil || len(m.KeepAlive) == 0 {
		return defaultKeepAlive
	}
	var secs float64
	if err := json.Unmarshal(m.KeepAlive, &secs); err == nil {
		return time.Duration(secs * float64(time.Second))
	}
	var s string
	if err := json.Unmarshal(m.KeepAlive, &s); err == nil {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return defaultKeepAlive
}

// newTimings synthesises a plausible timing breakdown for one completion.
func newTimings(model string, keepAlive time.Duration, promptTokens, evalTokens int) Timings {
	warm := models.touch(model, keepAlive)

	load := jitter(coldLoadMin, coldLoadMax)
	if warm {
		load = jitter(warmLoadMin, warmLoadMax)
	}
	t := Timings{
		Load:       load,
		PromptEval: time.Duration(promptTokens) * jitter(promptEvalPerTokenMin, promptEvalPerTokenMax),
		Eval:       time.Duration(evalTokens) * jitter(evalPerTokenMin, evalPerTokenMax),
	}
	// Real total_duration exceeds the sum of its parts by the request/sampling overhead.
	t.Total = t.Load + t.PromptEval + t.Eval + jitter(500*time.Microsecond, 4*time.Millisecond)
	return t
}
