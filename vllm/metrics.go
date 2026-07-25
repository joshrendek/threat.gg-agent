package vllm

import (
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// Prometheus text exposition for /metrics. Captured prod traffic makes this the single
// most-requested path on the vLLM honeypot (16 hits from 11 distinct IPs, largely Palo Alto
// Xpanse and similar fingerprinting scanners) and it previously returned a JSON 404 — the
// clearest signal on the honeypot that nothing was actually serving.
//
// Counters are derived from process uptime so consecutive scrapes advance monotonically, the
// way a real exporter behaves. A static body that never changes is its own tell.

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

var startedAt = time.Now()

// counterAt returns a monotonically increasing count for a metric accruing at roughly
// ratePerSecond, with a small deterministic offset so different metrics do not move in lockstep.
func counterAt(ratePerSecond, seed float64) float64 {
	elapsed := time.Since(startedAt).Seconds()
	return math.Floor(elapsed*ratePerSecond + seed)
}

type histBucket struct {
	le    string
	count float64
}

func writeHistogram(b *strings.Builder, name, help string, labels string, buckets []histBucket, sum float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	var total float64
	for _, bk := range buckets {
		total = bk.count
		fmt.Fprintf(b, "%s_bucket{%s,le=\"%s\"} %g\n", name, labels, bk.le, bk.count)
	}
	fmt.Fprintf(b, "%s_bucket{%s,le=\"+Inf\"} %g\n", name, labels, total)
	fmt.Fprintf(b, "%s_count{%s} %g\n", name, labels, total)
	fmt.Fprintf(b, "%s_sum{%s} %g\n", name, labels, sum)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	labels := fmt.Sprintf("model_name=%q", defaultModel)
	prompt := counterAt(41.7, 18422)
	gen := counterAt(12.3, 7311)
	success := counterAt(0.21, 143)
	running := float64(rand.Intn(3))

	var b strings.Builder
	fmt.Fprintf(&b, "# HELP vllm:cache_config_info Information of the LLMEngine CacheConfig\n"+
		"# TYPE vllm:cache_config_info gauge\n"+
		"vllm:cache_config_info{block_size=\"16\",cache_dtype=\"auto\",enable_prefix_caching=\"False\","+
		"gpu_memory_utilization=\"0.9\",num_gpu_blocks=\"7684\",num_cpu_blocks=\"2048\",swap_space_bytes=\"4294967296\"} 1.0\n")

	gauges := []struct {
		name, help string
		value      float64
	}{
		{"vllm:num_requests_running", "Number of requests currently running on GPU.", running},
		{"vllm:num_requests_swapped", "Number of requests swapped to CPU.", 0},
		{"vllm:num_requests_waiting", "Number of requests waiting to be processed.", 0},
		{"vllm:gpu_cache_usage_perc", "GPU KV-cache usage. 1 means 100 percent usage.", 0.0142 + running*0.031},
		{"vllm:cpu_cache_usage_perc", "CPU KV-cache usage. 1 means 100 percent usage.", 0},
		{"vllm:gpu_prefix_cache_hit_rate", "GPU prefix cache block hit rate.", -1},
		{"vllm:cpu_prefix_cache_hit_rate", "CPU prefix cache block hit rate.", -1},
		{"vllm:avg_prompt_throughput_toks_per_s", "Average prefill throughput in tokens/s.", 0},
		{"vllm:avg_generation_throughput_toks_per_s", "Average generation throughput in tokens/s.", 0},
	}
	for _, g := range gauges {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s{%s} %g\n",
			g.name, g.help, g.name, g.name, labels, g.value)
	}

	counters := []struct {
		name, help string
		value      float64
		extra      string
	}{
		{"vllm:num_preemptions", "Cumulative number of preemption from the engine.", 0, ""},
		{"vllm:prompt_tokens", "Number of prefill tokens processed.", prompt, ""},
		{"vllm:generation_tokens", "Number of generation tokens processed.", gen, ""},
		{"vllm:request_success", "Count of successfully processed requests.", success, ",finished_reason=\"stop\""},
	}
	for _, c := range counters {
		fmt.Fprintf(&b, "# HELP %s_total %s\n# TYPE %s_total counter\n%s_total{%s%s} %g\n",
			c.name, c.help, c.name, c.name, labels, c.extra, c.value)
	}

	writeHistogram(&b, "vllm:time_to_first_token_seconds", "Histogram of time to first token in seconds.", labels,
		[]histBucket{
			{"0.001", 0}, {"0.005", 0}, {"0.01", 2}, {"0.02", 11}, {"0.04", 37},
			{"0.06", 61}, {"0.08", 79}, {"0.1", 94}, {"0.25", 118}, {"0.5", 129},
			{"0.75", 133}, {"1.0", math.Floor(success * 0.97)}, {"2.5", success},
		}, success*0.18)
	writeHistogram(&b, "vllm:time_per_output_token_seconds", "Histogram of time per output token in seconds.", labels,
		[]histBucket{
			{"0.01", 4}, {"0.025", 58}, {"0.05", math.Floor(gen * 0.81)}, {"0.075", math.Floor(gen * 0.94)},
			{"0.1", math.Floor(gen * 0.98)}, {"0.15", gen},
		}, gen*0.031)
	writeHistogram(&b, "vllm:e2e_request_latency_seconds", "Histogram of end to end request latency in seconds.", labels,
		[]histBucket{
			{"1.0", math.Floor(success * 0.22)}, {"2.5", math.Floor(success * 0.61)},
			{"5.0", math.Floor(success * 0.88)}, {"10.0", math.Floor(success * 0.97)},
			{"15.0", success}, {"20.0", success}, {"30.0", success},
		}, success*3.4)
	writeHistogram(&b, "vllm:request_prompt_tokens", "Number of prefill tokens processed.", labels,
		[]histBucket{
			{"1", 0}, {"2", 0}, {"5", 3}, {"10", 19}, {"20", 52},
			{"50", math.Floor(success * 0.72)}, {"100", math.Floor(success * 0.91)},
			{"200", math.Floor(success * 0.99)}, {"500", success}, {"1000", success},
		}, prompt)
	writeHistogram(&b, "vllm:request_generation_tokens", "Number of generation tokens processed.", labels,
		[]histBucket{
			{"1", 2}, {"2", 6}, {"5", 24}, {"10", 61},
			{"20", math.Floor(success * 0.78)}, {"50", math.Floor(success * 0.95)},
			{"100", success}, {"200", success},
		}, gen)

	w.Header().Set("Content-Type", metricsContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
