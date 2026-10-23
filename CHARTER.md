# Charter: `redactlint`

**It does this one thing:** Report a Go type that holds security-relevant
material and does not render itself safely in every way Go can render it.

Concretely: a `go/analysis` analyzer that flags a named struct with an
unexported `string`, `[]byte`, or named-over-either field whose name matches a
configurable secret-ish pattern, when that struct does not implement all four
of `fmt.Stringer`, `fmt.Formatter`, `json.Marshaler` and `slog.LogValuer` —
naming precisely which are missing and which rendering each one controls. Plus
one escape hatch: a `//redact:plain` field comment that must state why.

**It must not contain:** Any redaction mechanism of its own — no logger, no
scrubber, no `Redact(v any)` helper. Any runtime code at all. Taint tracking,
dataflow analysis, or any attempt to decide whether a value *reaches* a log
sink. Any other lint, however adjacent: this is not a place to collect the
project's analyzers.

The analyzer answers "is this type capable of leaking?", not "does it leak?".
The second question is the conformance subtest's
(`NoSecretLeaksInAnyRendering`, duplicated into each module's `<module>test`
package), and it is answered by running the renderings rather than by
reasoning about them.

## Why this is its own module

It passes the test that justifies one, by the second of the two questions in
`CONVENTIONS.md` ("does sharing reduce risk, or only reduce typing?") rather
than the first.

**Can it be wrong?** Yes, and in the expensive direction: a false negative is a
credential in a log file. The interface-to-rendering mapping it encodes was
measured rather than read off the godoc, and it was wrong twice on the first
reading — `fmt` consults `Stringer` for exactly five verbs, and `GoStringer`
does control `%#v` contrary to the note this analyzer's convention originally
carried. That mapping is behaviour, it belongs in one place, and it belongs
with a test.

**But the reason it is not a package inside a library module is the dependency
graph.** The analyzer needs `golang.org/x/tools`. Housing it inside `keyring`,
`tenancy` or `audit` would put `x/tools` — and `x/mod`, and `x/sync` — into the
module graph of **every downstream consumer of that library**, for a tool no
consumer runs at run time. A library's module graph is part of what it asks of
its users, and asking for a compiler toolchain in order to ship a lint is not a
trade any of these modules should make.

The symmetric argument rules out the other placements:

| Where | Why not |
|---|---|
| a package in `keyring` | `x/tools` in every `keyring` consumer's graph; and the rule is not keyring's |
| a package in each module | the mapping duplicated nine times, which is the one thing it must not be |
| `cas/internal/lint` | not reusable, and `cas` is the consumer, not the owner |
| a `tools/` module in one repo | a nested module that no `go install` path names, and whose CI nobody wired |

It also has **no runtime consumers at all**, which is unusual in this set and
is what makes a separate release cadence free: nothing version-bumps because
`redactlint` did.

## The one thing it deliberately does not do: no golangci-lint plugin

`golangci-lint` can run a third-party analyzer only through its custom-linter
mechanism, which requires rebuilding `golangci-lint` itself from a plugin
module (`golangci-lint custom`) and then using that binary everywhere. Every
repository's CI would have to do that build before it could lint, and the
pinned `golangci-lint` version in nine `mise.toml` files would stop meaning
what it says.

So this ships as `cmd/redactlint`, a `singlechecker` binary, plus a `mise`
task. The cost is one task definition per repository and nothing in CI setup.
If `golangci-lint` ever gains plugin loading that does not require a rebuild,
this decision is worth revisiting and nothing else changes.

## Known limits, recorded so they are not rediscovered

These are deliberate, and each one is a place the conformance subtest covers
what the analyzer cannot:

- **Material behind a pointer or in a fixed-size array is not flagged.**
  `[32]byte` is almost always a digest, and a digest of stored content is not a
  secret — `audit` says so in its own source. `*string` holding material is a
  genuine gap, and it is also the documented mitigation for `%p`, the one verb
  no interface can control.
- **An anonymous struct type cannot be checked**, because it has no method set
  to check.
- **It does not follow material through a field of another struct type.** The
  convention's rule is wider than this: *every* type that transitively holds
  material carries the four interfaces itself, because redaction is not
  inherited through an unexported field. The analyzer checks the innermost
  type's container only.
- **`_test.go` files are skipped by default** (`-include-tests` turns them on).
  A fixture named `token` is a canary whose purpose is to be searched for in a
  rendering, and an analyzer whose output is mostly canaries is one people stop
  reading. A non-test file in a sibling test-helper package — `tenancy/testdb`,
  `keyring/keyringtest` — is checked either way, because those ship.
- **`%p` is outside what any of this can fix.** `fmt`'s bad-verb path sets its
  internal `erroring` flag before describing the operand, so `handleMethods`
  returns without consulting any interface and the operand is reflected. The
  mitigation is to hold the material behind a pointer field; the convention
  records it rather than mandating it.

## Adoption

| Consumer | State |
|---|---|
| keyring | clean; `mise run redact` |
| tenancy | clean; found `migrate.resolvedConfig`, which carried the migration DSN unexported and unrendered |
| iam | clean |
| audit | clean — nothing in the module qualifies, which is the correct answer rather than a gap |
| meter | clean — likewise |
| pgmigrate | clean — it takes a live handle, so no credential enters the module as text |
| captoken | **reports `chain.Minter.rootKey`, an `ed25519.PrivateKey` on a type with no rendering methods.** Not fixed here; the owner holds that tree |
| escrow, seal | chartered, no Go files yet; share material is squarely in scope when there is |

## Provenance

Extracted from the "Rendering a secret" convention, 2026-10-23, after the
conformance subtest it complements found three leaks in `keyring` and one in
`tenancy` on its first run — and after the obvious follow-up question ("what
about the types nobody registered a subtest for?") turned out to have no
answer. `captoken`'s `Minter` is that question's answer: the analyzer found it,
and no subtest would have.
