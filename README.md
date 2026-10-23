# redactlint

[![ci](https://github.com/laenenai/redactlint/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/redactlint/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/redactlint.svg)](https://pkg.go.dev/github.com/laenenai/redactlint)

Finds the types that can leak a secret through `fmt`.

A `go/analysis` analyzer for one rule: a type holding security-relevant
material must render itself safely in **every** way Go can render it, which
takes four interfaces. It reports which ones are missing.

> **Status: pre-1.0.** The analyzer and its fixtures are complete and tested
> against `go/analysis`'s own harness. It ships as a binary rather than a
> `golangci-lint` plugin, deliberately — see below.

## Install

```
go install github.com/laenenai/redactlint/cmd/redactlint@latest
```

```
redactlint ./...
redactlint -patterns=key,token,pepper ./...
```

Requires Go 1.25.6 or later. No cgo.

## Why four interfaces

Each of these was measured on go1.25.6, not read off the documentation, and
the documentation's summary misled on two of them.

| Rendering | Interface that controls it |
|---|---|
| `%v`, `%s`, `%q`, `%x`, `%X`, `print`, string concatenation | `fmt.Stringer` |
| every other verb — `%d`, `%c`, `%U`, `%b`, `%o`, `%#v`, width and precision forms | `fmt.Formatter` |
| `json.Marshal`, and everything built on it | `json.Marshaler` |
| `slog` attributes, under every handler | `slog.LogValuer` |

The trap is that four of the five are easy and the fifth is the one that
matters:

- **`fmt` consults `Stringer` for five verbs and no others.** A key type with
  `Stringer`, `GoStringer`, `MarshalText`, `MarshalJSON` *and* `LogValuer` —
  five interfaces, a package doc comment asserting that "key material never
  renders", and a unit test per rendering — still printed all 32 key bytes
  under `%d`. `fmt.Formatter` is the only interface consulted for every verb.
- **`json.Marshal` consults neither `Stringer` nor `TextMarshaler`.** A struct
  of only unexported fields marshals to `{}`, which is safe by accident; the
  accident ends the moment a field is exported or the type is a named `string`.
- **`slog` does not always call `String()`.** `TextHandler` formats a
  non-`LogValuer` with `%+v`, so `Stringer` happens to save it. `JSONHandler`
  calls `json.Marshal`, so `Stringer` does not.
- **`%p` cannot be fixed by any interface.** `fmt`'s bad-verb path sets its
  internal `erroring` flag before describing the operand, so `handleMethods`
  returns without consulting anything and the operand is reflected. Holding the
  material behind a pointer field closes it. This analyzer does not try.

## What it flags

A named struct with an unexported field of type `string`, `[]byte`, or a named
type over either, whose name matches a secret-ish substring, on a type that
does not implement all four:

```
internal/chain/chain.go:79:2: Minter holds security-relevant material in field
rootKey, but does not implement fmt.Stringer (which controls %v, %s, %q, %x,
%X, print, and string concatenation) or fmt.Formatter (which controls every
other verb, including %d, %c, %U, %b and %o, which consult no other interface)
or json.Marshaler (…) or slog.LogValuer (…)
```

**Unexported**, because an exported field of a redacting type is already
covered — `fmt` consults an exported field's own methods. The unexported case
is the one that is not covered, and it is the dangerous one: a value reached
through an unexported field fails `reflect.Value.CanInterface`, so `fmt`
abandons the method path for that whole subtree and prints it by raw
reflection, the field type's own redaction included.

The pattern list is a flag, defaulting to `key, secret, token, password,
passwd, credential, dsn, material, share, privatekey, seed`. Substrings, not
whole words, so `wrapKey`, `rootKey`, `apiToken` and `metadataDSN` all match.

## Opting out

A field whose name matches but holds nothing secret is exempted by a comment
that says why:

```go
type Record struct {
	//redact:plain — the key id, not the key
	keyID string
}
```

The rationale is required. A bare `//redact:plain` gets its own diagnostic,
because an exemption nobody justified is an exemption nobody reviewed.

## Why a binary and not a golangci-lint plugin

`golangci-lint` runs a third-party analyzer only through its custom-linter
mechanism, which means rebuilding `golangci-lint` from a plugin module and
using that binary everywhere. Every repository's CI would have to do that build
before it could lint, and the pinned `golangci-lint` version in each
`mise.toml` would stop meaning what it says.

So: `cmd/redactlint`, and one `mise` task per repository.

```toml
[tasks.redact]
description = "Report types that hold material and do not redact every rendering."
run = "go run github.com/laenenai/redactlint/cmd/redactlint@latest ./..."
```

## What it does not do

It answers *"is this type capable of leaking?"*, not *"does it leak?"* — there
is no taint tracking and no attempt to decide whether a value reaches a sink.
The second question belongs to the conformance subtest
`NoSecretLeaksInAnyRendering`, which lives in each module's `<module>test`
package and answers it by running the renderings rather than reasoning about
them. The two are complements: the subtest proves the rule for a value someone
remembered to register, and this analyzer exists for the types nobody
remembered.

It also contains no redaction mechanism of its own. There is deliberately no
logging module in this set of repositories, and no `Redact(v any)` helper:
redaction belongs on the type.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, and why `x/tools` in a library's module graph is the reason this is its own repository
- [`SECURITY.md`](SECURITY.md) — reporting, and what a clean run does and does not prove
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
