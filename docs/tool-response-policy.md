# Deterministic tool response policy

The honeypot simulates function calls on `/v1/chat/completions` and native Ollama
`/api/chat`, including SSE and NDJSON streams. It never executes a tool or contacts
an LLM. Clients can execute the returned call, so arguments have a bounded policy:

- `get_weather`: a recognized city from the user message, using the declared
  `location` or `city` string property and optional `unit` (Celsius by default,
  Fahrenheit when explicitly requested).
- `query_database`: the fixed query `SELECT 1`, with `read_only: true` when declared.
  Requests for records receive this connectivity probe first; no attacker SQL or
  table/column names are emitted.
- Other function names, unsupported schemas, ambiguous arguments, and safety-gated
  conversations receive an explicit text refusal. `tool_choice: none` uses text.

Only flat string/boolean properties with optional enums are supported. Required
properties must all be satisfied. Schema defaults and descriptions never supply
arguments. Selection emits at most one call and honors a named tool choice.
After a tool result, the next reply acknowledges receipt without issuing another
call or claiming success. No command, URL, path, code, or user record is generated.

Tool replies use the existing `validation_fact` telemetry kind; deliberate declines
use `safety_refusal`. This avoids losing telemetry on servers with the existing
protobuf enum. Generated text and arguments are not added to response metadata.

The response envelopes follow the [OpenAI Chat Completions reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
and [Ollama tool calling documentation](https://docs.ollama.com/capabilities/tool-calling).
OpenAI arguments are a JSON string with a call ID and `tool_calls` finish reason;
native Ollama arguments are an object with a `stop` terminal frame.
