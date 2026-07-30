package cmdresp

// PRD 034 required this package to be left alone, and said why: the LLM override path
// is a per-request control-plane lookup, and the prompt-rule corpus is deliberately
// NOT one. The reasoning ("the cache stops working", "the negative cache becomes
// attacker-steerable", "a real Ollama's latency is a fingerprint") only holds while
// this path stays keyed on METHOD plus path and stays inside its bounds.
//
// The existing tests in this package reference these constants symbolically, so they
// would keep passing if a value moved. These are literal pins: they fail if the
// numbers change, which is the point.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestLLMOverrideBoundsAreUnchangedByPRD034(t *testing.T) {
	bounds := []struct {
		name string
		got  any
		want any
	}{
		{"LLMOverrideTimeout", LLMOverrideTimeout, 250 * time.Millisecond},
		{"llmOverrideCacheTTL", llmOverrideCacheTTL, 30 * time.Second},
		{"maxLLMOverrideCache", maxLLMOverrideCache, 256},
		{"maxConcurrentLLMLookups", maxConcurrentLLMLookups, 32},
		{"MaxServerLookupLen", MaxServerLookupLen, 4096},
	}
	for _, b := range bounds {
		if b.got != b.want {
			t.Errorf("%s = %v, want %v", b.name, b.got, b.want)
		}
	}
	if cap(llmOverrideLookupSlots) != maxConcurrentLLMLookups {
		t.Errorf("lookup slot capacity = %d, want %d", cap(llmOverrideLookupSlots), maxConcurrentLLMLookups)
	}
}

// TestOverrideKeyIsStillMethodAndPathOnly. The whole "why not extend cmdresp" section
// of PRD 034 rests on this lookup never reading the request BODY: a body-keyed lookup
// would collapse the cache hit rate to near zero and fill the 256-entry negative cache
// with attacker-chosen prompt text.
//
// Asserted behaviourally (the key a lookup receives) and structurally (no
// r.Body/readBody reference anywhere in the package's non-test source), because the
// behavioural half alone would not catch a body read added alongside the path key.
func TestOverrideKeyIsStillMethodAndPathOnly(t *testing.T) {
	original := GetCommandResponseWithin
	t.Cleanup(func() { GetCommandResponseWithin = original })

	keys := make(chan string, 4)
	GetCommandResponseWithin = func(in *proto.CommandRequest, _ time.Duration) (*proto.CommandResponse, error) {
		keys <- in.GetCommand()
		return &proto.CommandResponse{Matched: false}, nil
	}

	handler := LLMMuxMiddleware("ollama")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/api/generate?model=x",
		strings.NewReader(`{"prompt":"a distinctive prompt body"}`))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	key := <-keys
	if key != "POST /api/generate" {
		t.Fatalf("lookup key = %q, want %q -- the query string and the body must not be part of it", key, "POST /api/generate")
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if ok && ident.Name == "r" && sel.Sel.Name == "Body" {
					t.Errorf("%s reads r.Body; the cmdresp override path must stay keyed on METHOD plus path (PRD 034)", path)
				}
				return true
			})
		}
	}
}
