package ollama

import "testing"

// Regression for the correlated-digest defect: an earlier pseudoDigest concatenated four FNV-1a
// hashes of the same name plus a counter, producing visibly repeating 8-byte blocks where a real
// sha256 is uniformly random.
func TestPseudoDigestHasNoRepeatingBlocks(t *testing.T) {
	for _, name := range []string{"llama3.2:1b", "mistral:7b", "qwen2.5:0.5b"} {
		d := pseudoDigest(name)
		if len(d) != 64 {
			t.Fatalf("%s: digest length %d, want 64", name, len(d))
		}
		seen := map[string]bool{}
		for i := 0; i+8 <= len(d); i += 8 {
			blk := d[i : i+8]
			if seen[blk] {
				t.Errorf("%s: repeated 8-char block %q in %s", name, blk, d)
			}
			seen[blk] = true
		}
		// The old bug made blocks differ only in one nibble; require real divergence.
		if d[0:6] == d[16:22] || d[0:6] == d[32:38] {
			t.Errorf("%s: correlated blocks in %s", name, d)
		}
	}
	if pseudoDigest("a") == pseudoDigest("b") {
		t.Error("digest is not name-dependent")
	}
	if pseudoDigest("a") != pseudoDigest("a") {
		t.Error("digest is not stable")
	}
}
