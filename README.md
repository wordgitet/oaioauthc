# oaioauthc

`oaioauthc` is a small C99, local-only OpenAI-compatible proxy for a ChatGPT
OAuth session. It is compatible with the core local routes of `openai-oauth`:
`/health`, `/v1/models`, `/v1/responses`, `/v1/chat/completions`,
`/v1/images/generations`, and `/v1/images/edits`.

## Build

Install `curl`, `openssl`, and `jansson` development packages, then run:

```sh
autoreconf -fi
./configure
make
make check
```

## Use

```sh
./src/oaioauthc login
./src/oaioauthc serve
```

The server binds to `127.0.0.1:10531` by default. Credentials are read from
`$CODEX_HOME/auth.json` or `~/.codex/auth.json`, unless `--oauth-file` is set.
Use `-p PORT` or `--port PORT` to select a different local listener port.
`login` waits five minutes for the browser callback by default; use
`--login-timeout-ms MS` to select a positive timeout. `--no-open` keeps the
browser closed, while `--open` requests the default desktop opener. Use
`--help` or `--version` to inspect the command-line interface.
Use `/v1/models` to discover the account's current models; Responses and Chat
Completions requests must specify one explicitly. The Codex client version is
discovered automatically at startup; use `--codex-version` to provide an
explicit version when the registry is unavailable.

Image generation and editing requests must also specify `model`; the proxy does
not hardcode an image-model name. Edits accept OpenAI-compatible
`multipart/form-data`, with `image` or `image[]` files, and convert up to five
50 MB reference images to the Codex JSON format. For `openai-oauth`
compatibility, streaming image requests, masks, and unsupported options return
an `invalid_request_error`.

Use `oaioauthc serve --debug-json` to print parsed client requests and
normalized Codex request JSON to stderr. Output is compact by default;
`--debug-json=pretty` selects indented output and `--debug-json=compact`
selects compact output explicitly. Image data URLs, token fields, and encrypted
reasoning content are redacted. Prompts, conversation history, and tool
definitions are not redacted; enable this flag only while debugging and protect
captured logs accordingly.

The project is unaffiliated with OpenAI; treat stored OAuth credentials as
passwords.

## License

BSD-2-Clause or CC0-1.0, at your option. See `COPYING`.
