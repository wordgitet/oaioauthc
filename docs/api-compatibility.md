# API compatibility

`oaioauthc` exposes a deliberately bounded OpenAI-compatible HTTP surface over
a ChatGPT OAuth session. It does not attempt to implement every OpenAI API
endpoint or retain server-side conversation state.

## Connection and authentication

The default API root is `http://127.0.0.1:10531/v1`. The proxy does not
authenticate incoming clients or use their `Authorization` headers. Except for
`GET /health`, every route loads the configured ChatGPT OAuth credentials and
refreshes them when necessary.

Do not expose the listener to an untrusted network. SDKs that require an API
key may use any non-empty placeholder value.

## Detached lifecycle

`oaioauthc serve --daemon` detaches without systemd or another service manager.
The process owns a private runtime directory containing `runtime.lock`,
`runtime.json`, `control.sock`, and `server.log`. `status`, `stop`, and
`logs --follow` communicate through the local control socket; they do not
treat stale metadata or a PID alone as proof that a daemon is alive.

## Supported routes

| Method | Route | Behavior |
| --- | --- | --- |
| `GET` | `/health` | Local health and replay state; no credentials loaded. |
| `GET` | `/v1/models` | Explicit IDs or the supported account catalog. |
| `POST` | `/v1/responses` | Buffered or SSE Responses requests. |
| `POST` | `/v1/chat/completions` | Buffered or streaming Chat conversion. |
| `POST` | `/v1/images/generations` | Supported JSON image generation. |
| `POST` | `/v1/images/edits` | Supported multipart image editing. |

Other method and path combinations return an OpenAI-style `not_found_error`.
Every model-dependent request must contain a non-empty `model`; the proxy never
hardcodes one.

## Responses and Chat Completions

The proxy has no persistent response store. Responses requests containing
`previous_response_id` or `item_reference` are rejected. Clients must replay
the complete conversation in `input`.

Responses are the internal upstream representation. Chat Completions messages,
tool calls, tool outputs, refusals, images, usage, and streaming events are
translated at the route boundary. The proxy forces upstream streaming even
for buffered client requests, then returns the completed response object.

## Images

Image generation requires JSON with non-empty `model` and `prompt`. The proxy
forwards `background`, `n`, `quality`, and `size` when present. The
`response_format` field may be omitted or set to `b64_json`.

Image editing requires `multipart/form-data`, non-empty `model` and `prompt`,
and at least one `image` or `image[]` file. It accepts at most five reference
images, each no larger than 50 MiB, and a total request body no larger than
256 MiB. It forwards `background`, `n`, `quality`, and `size` when present.

Streaming images and masks are rejected. The known incompatible fields
`input_fidelity`, `moderation`, `output_compression`, `output_format`, and
`partial_images` are also rejected. Other fields outside the forwarded subset
are not sent upstream. Image responses use `b64_json`.

## Limits and errors

Ordinary request bodies are limited to 8 MiB and request headers to 64 KiB.
An individual upstream SSE event is limited to 1 MiB, and a buffered upstream
response is limited to 64 MiB.

Local validation failures use an OpenAI-style JSON error object. Upstream HTTP
statuses, content types, and response bodies are preserved when an upstream
request completes with an error response. Transport and normalization failures
are returned as `upstream_error` or `server_error` responses as appropriate.
