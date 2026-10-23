package redactlint_test

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/laenenai/redactlint"
)

// TestAnalyzer runs the analyzer against testdata/src, where each package is
// a set of shapes taken from the laenen-ai modules as they actually stood:
// leaks holds what must be reported, redacted holds what must not, and
// exemptions covers the opt-out marker.
//
// analysistest is go/analysis's own harness and the `// want` comments in the
// fixtures are the expectations, so the fixtures are simultaneously the test
// and the documentation of what fires.
func TestAnalyzer(t *testing.T) {
	t.Parallel()

	analysistest.Run(t, analysistest.TestData(), redactlint.NewAnalyzer(),
		"leaks", "redacted", "exemptions", "testfiles")
}

// TestPatternsFlag proves the pattern list is genuinely configurable rather
// than configurable-looking: with -patterns=pepper,seal the default
// vocabulary must not fire and the configured one must.
func TestPatternsFlag(t *testing.T) {
	t.Parallel()

	a := redactlint.NewAnalyzer()
	if err := a.Flags.Set("patterns", "pepper,seal"); err != nil {
		t.Fatalf("set -patterns: %v", err)
	}
	analysistest.Run(t, analysistest.TestData(), a, "patterns")
}

// TestIncludeTestsFlag: with -include-tests the fixture in testfiles'
// _test.go file is reported too, which is what proves the default is a
// deliberate skip rather than an accident of how the files are loaded.
func TestIncludeTestsFlag(t *testing.T) {
	t.Parallel()

	a := redactlint.NewAnalyzer()
	if err := a.Flags.Set("include-tests", "true"); err != nil {
		t.Fatalf("set -include-tests: %v", err)
	}
	analysistest.Run(t, analysistest.TestData(), a, "testfilesincluded")
}

// TestPatternsParsing covers the flag's parsing rules directly. An empty list
// is refused rather than treated as "match nothing", because a flag that
// silently disables the analyzer is a flag that disables it by typo.
func TestPatternsParsing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{"trims and lowercases", " Key , TOKEN ", []string{"key", "token"}},
		{"drops empty entries", "key,,token,", []string{"key", "token"}},
		{"single entry", "pepper", []string{"pepper"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := redactlint.ParsePatternsForTest(tc.raw)
			if err != nil {
				t.Fatalf("ParsePatterns(%q): %v", tc.raw, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ParsePatterns(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}

	for _, raw := range []string{"", " ", " , ,", ",,,"} {
		if _, err := redactlint.ParsePatternsForTest(raw); err == nil {
			t.Errorf("ParsePatterns(%q) was accepted; an empty list must be refused", raw)
		} else if !strings.Contains(err.Error(), "-patterns is empty") {
			t.Errorf("ParsePatterns(%q) error = %v, want it to name the empty flag", raw, err)
		}
	}
}

// TestAnalyzerMetadata pins the parts of the analyzer a consumer's
// configuration names. Renaming the analyzer or the flag would silently
// disable whatever enabled it, so both are asserted rather than assumed.
func TestAnalyzerMetadata(t *testing.T) {
	t.Parallel()

	a := redactlint.NewAnalyzer()
	if a.Name != "redactlint" {
		t.Errorf("Name = %q, want redactlint", a.Name)
	}
	if a.Doc == "" {
		t.Error("Doc is empty; `redactlint -help` would say nothing")
	}
	if a.Flags.Lookup("patterns") == nil {
		t.Error("the -patterns flag is gone; every configuration naming it would fail")
	}

	// Two analyzers must not share flag state. A package-level Analyzer
	// would, and a test that set -patterns would then change the next one.
	first, second := redactlint.NewAnalyzer(), redactlint.NewAnalyzer()
	if err := first.Flags.Set("patterns", "pepper"); err != nil {
		t.Fatalf("set -patterns: %v", err)
	}
	if got := second.Flags.Lookup("patterns").Value.String(); !strings.Contains(got, "token") {
		t.Errorf("a second analyzer's -patterns = %q; the two share flag state", got)
	}
}

// TestDefaultPatternsCoverTheConventionsVocabulary pins the documented list.
// It is exported and named in CONVENTIONS.md, so shrinking it is a reviewed
// change rather than a quiet one.
func TestDefaultPatternsCoverTheConventionsVocabulary(t *testing.T) {
	t.Parallel()

	want := []string{
		"key", "secret", "token", "password", "passwd",
		"credential", "dsn", "material", "share", "privatekey", "seed",
	}
	got := strings.Join(redactlint.DefaultPatterns, ",")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("DefaultPatterns no longer covers %q", w)
		}
	}
	if len(redactlint.DefaultPatterns) != len(want) {
		t.Errorf("DefaultPatterns = %v, want exactly %v", redactlint.DefaultPatterns, want)
	}
}
