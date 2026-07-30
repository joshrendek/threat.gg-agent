# Ollama registry layers (`license` / `template` / `params`)

These are the documentary layers `/api/show` reports for the four advertised models that have no
full captured `/api/show` fixture in `../`. They exist because those four models were returning no
`license`, `template` or `parameters` at all, while a real `ollama show llama3.2` returns all
three — and `/api/show` is actively probed (threat_gg-y0i).

Every file is a **byte-exact blob from `registry.ollama.ai`**, not a transcription. Nothing here
was paraphrased, reflowed, or regenerated. Two details that look like mistakes are genuine and
must not be "fixed":

- `llama3.2_latest.template` contains the misspelling **`orginal`**. It is in Meta's shipped blob.
- `deepseek-r1_8b.*` use fullwidth **`｜` (U+FF5C)** and **`▁` (U+2581)**, not ASCII `|` and `_`.

`TestRegistryDocFixturesMatchRegistryDigests` checksums every file against the digest recorded in
its source manifest, so any edit fails the build.

## Provenance

| File | sha256 (= manifest layer digest) | Source |
| --- | --- | --- |
| `llama3.2_latest.template` | `966de95ca8a62200913e3f8bfbf84c8494536f1b94b49166851e76644e966396` | `library/llama3.2:latest` |
| `llama3.2_latest.params` | `56bb8bd477a519ffa694fc449c2413c6f0e1d3b1c88fa7e3c9d88d3ae49d4dcb` | `library/llama3.2:latest` |
| `mistral_latest.template` | `1ff5b64b61b9a63146475a24f70d3ca2fd6fdeec44247987163479968896fc0b` | `library/mistral:latest` |
| `llava_latest.template` | `c43332387573e98fdfad4a606171279955b53d891ba2500552c2984a6560ffb4` | `library/llava:latest` |
| `deepseek-r1_8b.template` | `c5ad996bda6eed4df6e3b605a9869647624851ac248209d22fd5e2c0cc1121d3` | `library/deepseek-r1:8b` |
| `deepseek-r1_8b.license` | `6e4c38e1172f42fdbff13edf9a7a017679fb82b0fde415a3e8b3c31c6ed4a4e4` | `library/deepseek-r1:8b` |
| `deepseek-r1_8b.params` | `ed8474dc73db8ca0d85c1958c91c3a444e13a469c2efb10cd777ca9baeaddcb7` | `library/deepseek-r1:8b` |
| `apache-2.0.license` | `43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1` | `library/mistral:latest` **and** `library/llava:latest` |
| `inst_stop.params` | `ed11eda7790d05b49395598a42b155812b17e263214292f7b87d15e14003d337` | `library/mistral:latest` **and** `library/llava:latest` |
| `llama3.2_latest.license` | `6de58700b9be15ef328dc638041e16c5aee6c576ba971b64200ccacfc0a60b5f` | join of two layers, below |

Two files are shared because `mistral:latest` and `llava:latest` genuinely ship **byte-identical**
license and params layers. `llava:latest` resolves to the v1.6-**Mistral** build
(`llava:7b-v1.6-mistral-q4_0`), not v1.5, so it inherits Mistral's Apache-2.0 and `[INST]` stop
tokens. Its template is the Mistral `[INST]` form — the vicuna `USER:`/`ASSISTANT:` template that
v1.5 used would be wrong here.

`llama3.2_latest.license` is not a single blob: that manifest carries **two** license layers and
the server joins them with `"\n"` (`License: strings.Join(m.License, "\n")` in `server/routes.go`).
The halves are:

- `fcc5a6bec9daf9b561a68827b67ab6088e1dba9d1fa2a50d7bbcc8384e0a265d` — Llama 3.2 Community License
- `a70ff7e570d97baaf4e62ac6e6ad9975e04caa6d900d3742d37698494479e0cd` — Acceptable Use Policy

Do not re-source that text from `llama.com` or Hugging Face: Ollama's blobs carry their own hard
wrapping and trailing whitespace that those copies do not reproduce.

## `.params` files are raw, not rendered

The `.params` files are the raw JSON params layer. `renderParameters` turns them into the flat
string `/api/show` reports, reproducing Ollama's own
`fmt.Sprintf("%-*s %#v", 30, key, value)` per value joined with newlines. That formatting is
pinned against the captured `gemma3:12b` fixture by
`TestRenderParametersMatchesCapturedFormatting`.

## No `system` layer

None of these four models defines a `SYSTEM` layer, so `/api/show` omits the field entirely. That
absence is correct and is asserted, not an oversight. (Of the two captured fixtures in `../`,
`qwen2.5-coder:7b` genuinely has a system layer but no params layer, and `gemma3:12b` is the
reverse.)

## Refreshing

```bash
model=llama3.2; tag=latest
curl -sS "https://registry.ollama.ai/v2/library/$model/manifests/$tag" |
  jq -r '.layers[] | select(.mediaType | test("template|license|params")) |
         "\(.mediaType)\t\(.digest)"'
curl -sSL "https://registry.ollama.ai/v2/library/$model/blobs/sha256:<digest>" -o <file>
shasum -a 256 <file>   # must equal <digest>
```

`-L` is required: the blob endpoint 307-redirects to object storage, and without it you silently
get a zero-length file. After refreshing, update the digest table above and the one in
`TestRegistryDocFixturesMatchRegistryDigests`.
