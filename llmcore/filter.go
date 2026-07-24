package llmcore

import "strings"

// apiSignalSegments is the set of second path segments under /api/ that belong to a real LLM
// serving API (Ollama's model/inference verbs, Ray's dashboard job/cluster endpoints). This
// keeps /api/tags, /api/generate, /api/jobs/… while rejecting generic /api/route, /api noise.
var apiSignalSegments = map[string]bool{
	"tags": true, "generate": true, "chat": true, "version": true, "ps": true,
	"show": true, "pull": true, "push": true, "create": true, "copy": true,
	"delete": true, "embeddings": true, "embed": true, "blobs": true,
	"jobs": true, "cluster_status": true, "serve": true, "packages": true,
	"actors": true, "nodes": true,
}

// exactSignalPaths are product-native LLM endpoints outside the /v1/ and /api/ families
// (llama.cpp /props /completion /slots, vLLM /health /metrics, ComfyUI /system_stats /prompt,
// LocalAI /models /readyz, Ray /nodes, …).
var exactSignalPaths = map[string]bool{
	"/models": true, "/props": true, "/health": true, "/readyz": true,
	"/metrics": true, "/version": true, "/slots": true, "/completion": true,
	"/completions": true, "/tokenize": true, "/detokenize": true,
	"/embedding": true, "/infill": true, "/system_stats": true,
	"/object_info": true, "/queue": true, "/history": true, "/prompt": true,
	"/nodes": true, "/interrupt": true,
}

// isSignalPath reports whether a request path targets a real LLM API surface — the OpenAI
// family (/v1/*), the Ollama/Ray /api/<verb> verbs, or a product-native endpoint. Everything
// else is generic internet scanning (/, favicon, nmap, proxy CONNECT, HTTP/2 PRI, Next.js RSC
// exploits, LFI probes, router CVEs) that the honeypot should still answer convincingly but
// must not persist — it drowns the real LLM-attack signal otherwise.
func isSignalPath(path string) bool {
	p := strings.ToLower(strings.TrimRight(path, "/"))
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/v1/") {
		return true
	}
	if strings.HasPrefix(p, "/api/") {
		seg := p[len("/api/"):]
		if i := strings.IndexByte(seg, '/'); i >= 0 {
			seg = seg[:i]
		}
		return apiSignalSegments[seg]
	}
	return exactSignalPaths[p]
}
