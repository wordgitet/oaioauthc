# oaioauthc contributor instructions

These instructions apply to the entire repository.

## Project direction

- Keep the program small, auditable, and compatible with `openai-oauth`.
- Use C99. Prefer ISO C; isolate required POSIX interfaces at system
  boundaries and do not use GNU-only language extensions.
- Use Autoconf and Automake. Edit `configure.ac` and `Makefile.am`, not their
  generated output.
- The established external dependencies are libcurl, OpenSSL, and Jansson.
  Do not add another dependency without discussing the cost and purpose first.
- Do not hardcode model names. Forward an explicit caller-selected model or
  discover models from the Codex endpoint.
- Keep the default server local-only and treat OAuth credentials as passwords.

## C style

- Follow BSD KNF as documented by `style(9)`.
- Indent with tabs according to KNF; do not use spaces as indentation.
- Keep lines near 80 columns and wrap function calls and declarations in KNF
  form.
- Use lower-case `snake_case` for functions, variables, fields, and file names.
  Never introduce camelCase or PascalCase identifiers.
- Put declarations at the beginning of their block.
- Use braces for multi-line control flow and preserve the surrounding style.
- Check allocation, integer bounds, I/O results, and ownership on every new
  path.
- Keep parsing length-aware. Do not use string functions on untrusted binary
  request bodies.

## Development workflow

1. Inspect `git status` and the relevant code before editing.
2. Preserve unrelated user changes and keep each change narrowly scoped.
3. Add or update tests with the implementation. Prefer deterministic unit
   tests and local mock servers over live requests or real credentials.
4. Build from the Autotools source:

       autoreconf -fi
       ./configure
       make
       make check

5. Run `git diff --check`. For release-facing or build-system changes, also run
   `make distcheck`.
6. Review the staged diff before committing. Do not amend, rebase, push, or
   rewrite published history unless explicitly requested.

The normal compiler flags include C99 mode, `-Wall`, `-Wextra`, `-Wpedantic`,
and `-Werror`. Fix warnings rather than suppressing them.

## Compatibility tests

- Cover OpenAI request and response shapes as well as Codex normalization.
- Include malformed input, size and count limits, binary data, streaming,
  multi-turn history, upstream errors, and allocation-sensitive boundaries
  where relevant.
- Keep process-level tests for public routes and focused unit tests for
  parsers and converters.
- A change is incomplete while a safe, relevant test is failing.

## Commit messages

Use Linux-kernel-style commit messages. Do not use Conventional Commit or
semantic prefixes such as `feat:`, `fix:`, `refactor:`, or `chore:`.

The subject format is:

    subsystem: imperative summary

- Name the affected subsystem, such as `proxy`, `images`, `auth`, or `build`.
- Write the summary in imperative mood.
- Describe the change and its purpose, not a file name.
- Keep the subject within 70-75 characters and omit the trailing period.
- Separate the subject and body with a blank line.
- Use a self-contained body for every non-trivial change. Explain the problem
  or user-visible symptom first, then explain why the chosen implementation
  solves it. Wrap body text at 75 columns.
- Prefer prose to a change inventory. If a message needs a list of unrelated
  changes, split the commit.
- Solve one logical problem per commit.
- Refer to existing commits with at least 12 hexadecimal characters and their
  subject.
- Add `Fixes:`, `Reported-by:`, `Reviewed-by:`, `Signed-off-by:`, and similar
  trailers only when accurate and authorized. Never invent attribution.
- Do not add AI attribution or tool-generated-message trailers.

Example:

    json: encode assistant history as output text

    Open WebUI replays assistant messages when a conversation continues.
    Encoding those messages as input_text makes the Responses endpoint reject
    streamed follow-up requests.

    Emit output_text for assistant content while retaining input_text for
    user and developer messages.
