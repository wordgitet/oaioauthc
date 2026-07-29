# oaioauthc

`oaioauthc` is a small C99, local-only OpenAI-compatible proxy for a ChatGPT
OAuth session. It is compatible with the core local routes of `openai-oauth`:
`/health`, `/v1/models`, `/v1/responses`, `/v1/chat/completions`,
`/v1/images/generations`, and `/v1/images/edits`.

> [!WARNING]
> The proxy has no inbound authentication layer. Keep it bound to loopback and
> treat its OAuth credential file as a password.

## Build

Install `curl`, `openssl`, and `jansson` development packages, then run:

```sh
autoreconf -fi
./configure
make
make check
```

## Quick start

```sh
./src/oaioauthc login
./src/oaioauthc serve
```

On a headless machine, authorize from another trusted device instead of
starting a local browser:

```sh
./src/oaioauthc login --device-auth
```

The command prints an OpenAI verification URL and one-time code, polls for
approval for up to 15 minutes, and writes the same Codex-compatible
`auth.json` used by the proxy. Device authorization is a beta OpenAI feature;
enable it in ChatGPT security or workspace settings if the endpoint says it
is unavailable. Enter the code only when you started the login yourself; a
code supplied by a website or another person may be a phishing attempt.

The server listens on `http://127.0.0.1:10531` by default. Discover the models
available to the signed-in account:

```sh
curl -sS http://127.0.0.1:10531/v1/models
```

Then replace `MODEL_ID` with an ID returned above:

```sh
curl -sS http://127.0.0.1:10531/v1/responses \
    -H 'Content-Type: application/json' \
    -d '{"model":"MODEL_ID","input":"Say hello in one sentence."}'
```

Clients that require an API-key setting may use any non-empty placeholder; the
proxy authenticates upstream with the saved OAuth session.

For a detached process with no system service manager:

```sh
./src/oaioauthc serve --daemon
./src/oaioauthc status
./src/oaioauthc logs --follow
./src/oaioauthc stop
```

The daemon stores its lock, status, control socket, and log below
`$XDG_STATE_HOME/oaioauthc` (or `$HOME/.local/state/oaioauthc`). Use
`--runtime-dir DIR` when an explicit private state directory is required.

## Documentation

- `man oaioauthc` after installation provides the complete command reference.
- [API compatibility](docs/api-compatibility.md) lists supported behavior and
  explicit limitations.
- [AI assistance policy](AI_DISCLOSURE.md) defines disclosure and authorship
  requirements for contributions.
- `oaioauthc --help` prints the installed version's command syntax.

For a local ASan and UBSan run, configure a clean build with
`./configure --enable-sanitizers`, then run `make check`.

This project is unaffiliated with OpenAI.

## License

BSD-2-Clause or CC0-1.0, at your option. See `COPYING`.
