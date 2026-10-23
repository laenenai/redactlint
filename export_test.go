package redactlint

// Test-only exports. They live here rather than in redactlint.go because a
// test-only identifier in a non-test file leaks into api.txt, and the public
// surface of this module is one constructor, one constant and one default
// list — see CONVENTIONS.md's note about ExportEntryDomainTag.

// ParsePatternsForTest exposes the -patterns parser, so the "an empty list is
// refused" rule can be asserted directly. Asserting it through analysistest
// is not possible: analysistest reports an analyzer error as a test failure,
// which is correct for every analyzer error except the one a test wants.
var ParsePatternsForTest = parsePatterns
