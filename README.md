# oaioauthc

`oaioauthc` is a small C99, local-only OpenAI-compatible proxy for a ChatGPT
OAuth session. It is compatible with the core local routes of `openai-oauth`:
`/health`, `/v1/models`, `/v1/responses`, and `/v1/chat/completions`.

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
Use `/v1/models` to discover the account's current models; Responses and Chat
Completions requests must specify one explicitly. The Codex client version is
discovered automatically and can be pinned with `--codex-version`.

Image-generation routes are not implemented.

The project is unaffiliated with OpenAI; treat stored OAuth credentials as
passwords.

## License

BSD-2-Clause or CC0-1.0, at your option. See `COPYING`.
