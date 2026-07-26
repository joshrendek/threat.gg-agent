# Ollama `/api/show` fixtures

These fixtures were captured from a local Ollama 0.30.11 installation on
2026-07-26. The source models were:

- `qwen2.5-coder:7b`, manifest digest
  `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- `gemma3:12b`, manifest digest
  `f4031aab637d1ffa37b42570452ae0e4fad0314754d17ded67322e4b95836f8a`

Each file is the compact JSON returned by `POST /api/show`. The capture only
normalizes `modified_at` to an empty string and the local model-store prefix to
`/root/.ollama`; the handler replaces `modified_at` with its stable catalog
timestamp.

To refresh a fixture against a newer Ollama release:

```bash
curl -sS http://127.0.0.1:11434/api/show \
  -d '{"model":"qwen2.5-coder:7b"}' |
  jq -c '.modified_at = "" | .modelfile |=
    gsub("/Users/[^/]+"; "/root")'
```

Run the live-reference test after any refresh:

```bash
OLLAMA_REFERENCE_URL=http://127.0.0.1:11434 \
  go test ./ollama -run Reference -v -count=1
```
