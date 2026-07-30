package vllm

import (
	"io"
	"net/http"
)

// vLLM's build_app installs FastAPI's CORSMiddleware unconditionally — there is no flag that
// turns it off — wired to the defaults in vllm/entrypoints/openai/cli_args.py:
//
//	app.add_middleware(
//	    CORSMiddleware,
//	    allow_origins=args.allowed_origins,      # default ["*"]
//	    allow_credentials=args.allow_credentials,# store_true, so default False
//	    allow_methods=args.allowed_methods,      # default ["*"]
//	    allow_headers=args.allowed_headers,      # default ["*"]
//	)
//
// So every internet-exposed vLLM is wide open to browsers, and sending no CORS headers at all was
// a one-request diff for any browser-based scanner. The Ollama honeypot already answers CORS; the
// values below are deliberately *not* copied from it, because the two servers genuinely differ:
// Ollama's Gin middleware advertises a fixed header allow-list and a 43200s max-age, Starlette
// mirrors the requested headers and defaults to 600.
//
// Everything here is starlette/middleware/cors.py with those four settings resolved at
// construction time:
//
//   - allow_methods=["*"] is expanded to ALL_METHODS, giving corsAllowMethods below.
//   - allow_origins=["*"] with credentials off makes preflight_explicit_allow_origin False, so a
//     preflight answers a literal "*" and sends no Vary.
//   - allow_headers=["*"] sets allow_all_headers, which suppresses the static
//     Access-Control-Allow-Headers and instead mirrors Access-Control-Request-Headers verbatim.
//   - allow_credentials False means no Access-Control-Allow-Credentials on either path.
//   - max_age is not passed, so it keeps the 600 default.

// corsAllowMethods is Starlette's ALL_METHODS tuple joined in its literal declaration order.
// That is a source-level tuple, not a set iteration, so the order is stable and safe to pin.
// Note it omits TRACE and CONNECT.
const corsAllowMethods = "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT"

// corsMaxAge is CORSMiddleware's default max_age. vLLM has no CLI flag for it.
const corsMaxAge = "600"

// corsAllowedMethods is the same tuple as a set, for the `requested_method not in
// self.allow_methods` membership test in preflight_response. The comparison is against uppercase
// entries and Starlette does not normalise the header, so a lowercase "get" genuinely fails it.
var corsAllowedMethods = map[string]bool{
	http.MethodDelete:  true,
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodPatch:   true,
	http.MethodPost:    true,
	http.MethodPut:     true,
}

// corsHeaders reproduces CORSMiddleware.__call__. It sits above the cmdresp override so an
// admin-authored response still carries CORS (the jenkins/ollama ordering pattern), and below
// identityHeaders because uvicorn is outermost in the real stack: it stamps Server even on the
// preflight response, which CORSMiddleware generates without ever entering the app.
func corsHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// The middleware returns before it touches the response when there is no Origin, so
			// a plain curl sees no CORS headers whatsoever. Stamping them unconditionally would
			// be its own tell in the opposite direction.
			next.ServeHTTP(w, r)
			return
		}
		// Starlette branches on header *presence*, not on a non-empty value, so a present but
		// empty Access-Control-Request-Method is still treated as a preflight (and then fails
		// the method check below).
		if _, isPreflight := r.Header[http.CanonicalHeaderKey("Access-Control-Request-Method")]; isPreflight && r.Method == http.MethodOptions {
			writePreflight(w, r)
			return
		}
		h := w.Header()
		if _, hasCookie := r.Header[http.CanonicalHeaderKey("Cookie")]; hasCookie {
			// simple_response's send() downgrades the wildcard to the caller's own origin when
			// the request carried cookies, since "*" is invalid for a credentialed response, and
			// marks the answer as origin-varying.
			h.Set("Access-Control-Allow-Origin", origin)
			addVary(h, "Origin")
		} else {
			h.Set("Access-Control-Allow-Origin", "*")
		}
		next.ServeHTTP(w, r)
	})
}

// writePreflight reproduces CORSMiddleware.preflight_response. Two details matter beyond the
// headers: the reply is a PlainTextResponse, so text/plain rather than FastAPI's bare
// application/json, and it never reaches the router — a preflight for a path this server does not
// route still answers 200, not 404.
func writePreflight(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", corsAllowMethods)
	h.Set("Access-Control-Max-Age", corsMaxAge)
	// allow_all_headers means "we have to mirror back any requested headers", verbatim and
	// unsorted, rather than answering with a fixed allow-list.
	if requested, ok := r.Header[http.CanonicalHeaderKey("Access-Control-Request-Headers")]; ok {
		h.Set("Access-Control-Allow-Headers", requested[0])
	}
	status, body := http.StatusOK, "OK"
	if !corsAllowedMethods[r.Header.Get("Access-Control-Request-Method")] {
		// Starlette answers a preflight it would not permit with a 400 and a description of
		// which check failed, keeping the headers it had already assembled. With wildcard origins
		// and headers, the method is the only check that can fail here.
		status, body = http.StatusBadRequest, "Disallowed CORS method"
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// addVary is MutableHeaders.add_vary_header: append to an existing Vary rather than replace it.
func addVary(h http.Header, value string) {
	if existing := h.Get("Vary"); existing != "" {
		h.Set("Vary", existing+", "+value)
		return
	}
	h.Set("Vary", value)
}
