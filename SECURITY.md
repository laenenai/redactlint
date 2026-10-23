# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

## Scope and status

This module is **pre-1.0**. The API may change, and it has not had an external
security review. Do not deploy it where a failure would be material without
reading `CHARTER.md` — in particular its stated non-contents, which are the
guarantees this module explicitly does **not** make.

## What a clean run proves, and what it does not

A clean `redactlint` run proves that every type it *can* see holds no
unexported, secret-named `string` or `[]byte` field without the four rendering
interfaces. It does not prove that nothing leaks.

Specifically, it says nothing about:

- material held behind a pointer, in a fixed-size array, or in an anonymous
  struct type;
- a field whose name does not match the configured pattern list;
- a field exempted by a `//redact:plain` comment, which is a human assertion
  and is only as good as its review;
- whether a value with all four methods renders *correctly* — a `String()` that
  returns the secret satisfies the analyzer completely;
- `%p`, which no implementation can control.

The question it answers is "is this type capable of leaking?". Whether a type
actually leaks is answered by running the renderings, which is what the
`NoSecretLeaksInAnyRendering` conformance subtest in each module's
`<module>test` package does. Neither mechanism replaces the other, and
`CHARTER.md` records which gaps are whose.
