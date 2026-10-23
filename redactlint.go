// Package redactlint is a go/analysis analyzer for one rule:
//
//	A type that holds security-relevant material must render itself safely
//	in every way Go can render it.
//
// The rule, and the measurements behind it, are in the shared modules'
// CONVENTIONS.md under "Rendering a secret". The short version is that four
// interfaces are needed and a subset is a trap:
//
//   - fmt.Stringer controls %v, %s, %q, %x and %X — and no other verb.
//   - fmt.Formatter controls every verb, which is the only reason it is
//     required: a type with Stringer, GoStringer, MarshalText, MarshalJSON and
//     LogValuer still printed all 32 bytes of a key under %d, because %d
//     consults none of them.
//   - json.Marshaler controls json.Marshal, and therefore slog's JSONHandler.
//   - slog.LogValuer controls structured attributes under every handler.
//     slog's TextHandler formats a non-LogValuer with %+v, so Stringer happens
//     to cover it; JSONHandler calls json.Marshal, so Stringer does not.
//
// The conformance subtest NoSecretLeaksInAnyRendering proves the rule for a
// value somebody remembered to register. This analyzer exists for the types
// nobody remembered, which is the larger set.
//
// # What it flags
//
// A named struct type with an unexported field whose type is string, []byte,
// or a named type over either, and whose name matches one of a configurable
// list of secret-ish substrings, when that struct does not implement all four
// interfaces. The diagnostic names precisely which interfaces are missing and
// which rendering each one would have controlled.
//
// Unexported, because an exported field of a redacting type is already
// covered: fmt consults an exported field's own methods. An unexported field
// is the case that is not covered, and it is the dangerous one — a value
// reached through an unexported field fails reflect.Value.CanInterface, so fmt
// abandons the method path for that whole subtree and prints it by raw
// reflection, the field type's own redaction included.
//
// # Opting out
//
// A field whose name matches the pattern but holds no material is exempted by
// a marker comment that states why:
//
//	type Record struct {
//		//redact:plain — the key id, not the key
//		keyID string
//	}
//
// The rationale is required. A bare //redact:plain is reported as its own
// diagnostic, because an exemption nobody justified is an exemption nobody
// reviewed.
//
// # Known limits, written down rather than discovered
//
//   - It does not flag material behind a pointer or in a fixed-size array.
//     [32]byte is usually a digest, which is not a secret; *string holding
//     material is a real gap, and it is also the documented mitigation for %p,
//     the one verb no interface can control.
//   - It cannot check an anonymous struct type, which has no method set to
//     check. Material in one is invisible to this analyzer.
//   - It does not follow material through a field of another struct type. The
//     convention's rule — every type that transitively holds material carries
//     the four interfaces itself — is wider than what is checked here.
//   - It skips _test.go files by default, because a test fixture named "token"
//     is a canary rather than material, and an analyzer whose output is mostly
//     noise is one people stop reading. -include-tests turns them on. A
//     non-test file in a sibling test-helper package — tenancy's testdb,
//     keyring's keyringtest — is checked either way: those ship.
package redactlint

import (
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// DefaultPatterns is the list of case-insensitive substrings that make a
// field name secret-ish. It is a default rather than a fixed set because the
// vocabulary is a property of a codebase, not of Go: a deployment whose
// secrets are called "pepper" or "seal" configures that instead of renaming
// its fields to satisfy a linter.
//
// They are substrings and not whole words on purpose. "wrapKey", "rootKey",
// "apiToken" and "metadataDSN" all have to match, and a word-boundary rule
// over camelCase would be a second thing to get wrong.
var DefaultPatterns = []string{
	"key",
	"secret",
	"token",
	"password",
	"passwd",
	"credential",
	"dsn",
	"material",
	"share",
	"privatekey",
	"seed",
}

// OptOutMarker is the comment prefix that exempts a field. It must be
// followed by a rationale.
const OptOutMarker = "redact:plain"

// requiredInterfaces are the four, each with the rendering it controls. The
// order is the order they are reported in, which is the order a reader needs:
// Stringer first because it is the one people already have, Formatter second
// because it is the one they are missing.
var requiredInterfaces = []struct {
	name     string
	method   string
	controls string
	// satisfied reports whether m is that interface's method, by
	// signature rather than by name alone.
	satisfied func(m *types.Func) bool
}{
	{
		name:      "fmt.Stringer",
		method:    "String",
		controls:  "%v, %s, %q, %x, %X, print, and string concatenation",
		satisfied: isStringMethod,
	},
	{
		name:      "fmt.Formatter",
		method:    "Format",
		controls:  "every other verb, including %d, %c, %U, %b and %o, which consult no other interface",
		satisfied: isFormatMethod,
	},
	{
		name:      "json.Marshaler",
		method:    "MarshalJSON",
		controls:  "json.Marshal, and slog's JSONHandler, which is built on it",
		satisfied: isMarshalJSONMethod,
	},
	{
		name:      "slog.LogValuer",
		method:    "LogValue",
		controls:  "structured log attributes under every handler",
		satisfied: isLogValueMethod,
	},
}

// config holds the analyzer's flags. It is a struct rather than package
// variables so that two Analyzer values, or two test runs, cannot share
// state.
type config struct {
	patterns     string
	includeTests bool
}

// NewAnalyzer returns a fresh analyzer with its own flag state.
//
// It is a constructor rather than a package-level variable because flag.FlagSet
// is mutable: a package-level Analyzer shared between a test that sets
// -patterns and one that does not makes the second test depend on the first.
func NewAnalyzer() *analysis.Analyzer {
	cfg := &config{patterns: strings.Join(DefaultPatterns, ",")}

	fs := flag.NewFlagSet("redactlint", flag.ExitOnError)
	fs.StringVar(&cfg.patterns, "patterns", cfg.patterns,
		"comma-separated, case-insensitive substrings that make a field name secret-ish; "+
			"a field matching one must be on a type implementing fmt.Stringer, fmt.Formatter, "+
			"json.Marshaler and slog.LogValuer, or carry a //"+OptOutMarker+" comment saying why not")
	fs.BoolVar(&cfg.includeTests, "include-tests", false,
		"also check _test.go files, whose fixtures are canaries rather than material")

	return &analysis.Analyzer{
		Name:     "redactlint",
		Doc:      analyzerDoc,
		Flags:    *fs,
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run:      func(pass *analysis.Pass) (any, error) { return run(cfg, pass) },
	}
}

const analyzerDoc = `check that a type holding security-relevant material redacts itself in every rendering

A struct with an unexported string or []byte field whose name looks like a
secret must implement fmt.Stringer, fmt.Formatter, json.Marshaler and
slog.LogValuer. A subset is not enough: fmt consults Stringer for %v, %s, %q,
%x and %X and for no other verb, json.Marshal consults neither, and slog's
JSONHandler is built on json.Marshal.

Exempt a field that holds no material with a comment stating why:

	//redact:plain — the key id, not the key
	keyID string`

func run(cfg *config, pass *analysis.Pass) (any, error) {
	patterns, err := parsePatterns(cfg.patterns)
	if err != nil {
		return nil, err
	}

	insp, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	if !ok {
		return nil, fmt.Errorf("redactlint: the inspect analyzer's result is %T, not *inspector.Inspector", pass.ResultOf[inspect.Analyzer])
	}

	insp.Preorder([]ast.Node{(*ast.TypeSpec)(nil)}, func(n ast.Node) {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			return
		}
		if !cfg.includeTests && isTestFile(pass, spec.Pos()) {
			return
		}
		checkStruct(pass, patterns, spec, st)
	})

	return nil, nil
}

// isTestFile reports whether pos is in a _test.go file.
//
// Those are skipped by default, and the reason is that a test's fixtures are a
// canary with a name like "token" or "key" — a value whose entire purpose is to
// be searched for in a rendering — rather than material a running system
// holds. Reporting them would make the analyzer's output mostly noise, and an
// analyzer whose output is mostly noise is one people stop reading. -include-tests
// turns them back on for a codebase that wants it.
//
// Note what this does NOT skip: a non-test file in a sibling test-helper
// package, such as tenancy's testdb or keyring's keyringtest. Those ship as
// ordinary packages, a consumer imports them, and their types are checked.
func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	f := pass.Fset.File(pos)
	return f != nil && strings.HasSuffix(f.Name(), "_test.go")
}

// parsePatterns splits and normalizes the -patterns flag. An empty list is an
// error rather than "match nothing": a flag that silently disables the
// analyzer is a flag that disables it by typo.
func parsePatterns(raw string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("redactlint: -patterns is empty; pass at least one substring, or do not enable this analyzer")
	}
	return out, nil
}

func checkStruct(pass *analysis.Pass, patterns []string, spec *ast.TypeSpec, st *ast.StructType) {
	obj, ok := pass.TypesInfo.Defs[spec.Name].(*types.TypeName)
	if !ok {
		return
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		// An alias to a struct type. The methods belong to whatever it
		// aliases, which is checked where that type is declared.
		return
	}

	var flagged []*ast.Field
	for _, field := range st.Fields.List {
		for _, name := range field.Names {
			if !isCandidateFieldName(name.Name, patterns) {
				continue
			}
			if !holdsMaterial(pass, field.Type) {
				continue
			}
			switch exemption(field) {
			case exemptWithReason:
				continue
			case exemptWithoutReason:
				pass.Reportf(name.Pos(),
					"field %s is exempted by //%s with no reason given; state why this field need not redact, as in \"//%s — the key id, not the key\"",
					name.Name, OptOutMarker, OptOutMarker)
				continue
			case notExempt:
				flagged = append(flagged, field)
			}
			break
		}
	}
	if len(flagged) == 0 {
		return
	}

	missing := missingInterfaces(named)
	if len(missing) == 0 {
		return
	}

	for _, field := range flagged {
		pass.Reportf(field.Pos(),
			"%s holds security-relevant material in %s, but does not implement %s; "+
				"each rendering must yield a fixed placeholder that names the type and carries neither the material nor its length "+
				"(or exempt the field with \"//%s — <why this field need not redact>\")",
			types.TypeString(named, relativeTo(pass)), fieldDescription(field), strings.Join(missing, " or "), OptOutMarker)
	}
}

// fieldDescription names the flagged field or fields as a reader would.
func fieldDescription(field *ast.Field) string {
	names := make([]string, 0, len(field.Names))
	for _, n := range field.Names {
		names = append(names, n.Name)
	}
	if len(names) == 1 {
		return "field " + names[0]
	}
	return "fields " + strings.Join(names, ", ")
}

// relativeTo renders a type name without the analyzed package's own path, so
// a diagnostic reads "Config" rather than the full import path.
func relativeTo(pass *analysis.Pass) types.Qualifier {
	return types.RelativeTo(pass.Pkg)
}

// isCandidateFieldName reports whether name is unexported and matches one of
// the secret-ish patterns.
func isCandidateFieldName(name string, patterns []string) bool {
	if name == "" || name == "_" {
		return false
	}
	if r := []rune(name)[0]; !unicode.IsLower(r) && r != '_' {
		// Exported. An exported field of a redacting type is already
		// covered, because fmt consults an exported field's own methods;
		// an exported field of a plain string is the consumer's own
		// struct to render, and flagging it here would report the same
		// material twice.
		return false
	}
	lower := strings.ToLower(name)
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// holdsMaterial reports whether the field's type is one this analyzer can
// recognize as holding material: string, []byte, or a named type over either.
func holdsMaterial(pass *analysis.Pass, expr ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(expr)
	if t == nil {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String
	case *types.Slice:
		b, ok := u.Elem().Underlying().(*types.Basic)
		return ok && (b.Kind() == types.Byte || b.Kind() == types.Uint8)
	default:
		return false
	}
}

type exemptionKind int

const (
	notExempt exemptionKind = iota
	exemptWithReason
	exemptWithoutReason
)

// exemption reads the field's doc and line comments for the opt-out marker.
//
// Both are checked because both are idiomatic: a marker above the field reads
// as documentation and one beside it reads as an annotation, and a convention
// that only accepted one would be a convention people worked around.
func exemption(field *ast.Field) exemptionKind {
	kind := notExempt
	for _, group := range []*ast.CommentGroup{field.Doc, field.Comment} {
		if group == nil {
			continue
		}
		for _, c := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(c.Text, "//"), "/*"))
			if !strings.HasPrefix(text, OptOutMarker) {
				continue
			}
			reason := strings.TrimSpace(strings.TrimPrefix(text, OptOutMarker))
			reason = strings.TrimLeft(reason, "-—:– \t")
			reason = strings.TrimSuffix(strings.TrimSpace(reason), "*/")
			if strings.TrimSpace(reason) != "" {
				return exemptWithReason
			}
			kind = exemptWithoutReason
		}
	}
	return kind
}

// missingInterfaces reports which of the four required interfaces named does
// not implement, each with the rendering it controls.
//
// Both the value and the pointer method sets are considered: a method with a
// pointer receiver is the right choice for a type holding a sync.Mutex, since
// a value receiver would copy the lock, and a consumer holds the pointer
// anyway.
func missingInterfaces(named *types.Named) []string {
	var missing []string
	for _, want := range requiredInterfaces {
		if hasMethod(named, want.method, want.satisfied) {
			continue
		}
		missing = append(missing, fmt.Sprintf("%s (which controls %s)", want.name, want.controls))
	}
	return missing
}

func hasMethod(named *types.Named, name string, satisfied func(*types.Func) bool) bool {
	for _, t := range []types.Type{named, types.NewPointer(named)} {
		for sel := range types.NewMethodSet(t).Methods() {
			fn, ok := sel.Obj().(*types.Func)
			if ok && fn.Name() == name && satisfied(fn) {
				return true
			}
		}
	}
	return false
}

// The four signature checks below match on structure rather than on the
// interface type itself, so the analyzer does not need fmt, encoding/json or
// log/slog to be in the analyzed package's import graph in order to recognize
// a method that satisfies one.

func isStringMethod(m *types.Func) bool {
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return false
	}
	b, ok := sig.Results().At(0).Type().Underlying().(*types.Basic)
	return ok && b.Kind() == types.String
}

func isFormatMethod(m *types.Func) bool {
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 2 || sig.Results().Len() != 0 {
		return false
	}
	if !isNamedFrom(sig.Params().At(0).Type(), "fmt", "State") {
		return false
	}
	b, ok := sig.Params().At(1).Type().Underlying().(*types.Basic)
	return ok && b.Kind() == types.Int32 // rune
}

func isMarshalJSONMethod(m *types.Func) bool {
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 2 {
		return false
	}
	s, ok := sig.Results().At(0).Type().Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, ok := s.Elem().Underlying().(*types.Basic)
	if !ok || (b.Kind() != types.Byte && b.Kind() != types.Uint8) {
		return false
	}
	return types.Universe.Lookup("error").Type() == sig.Results().At(1).Type()
}

func isLogValueMethod(m *types.Func) bool {
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return false
	}
	return isNamedFrom(sig.Results().At(0).Type(), "log/slog", "Value")
}

// isNamedFrom reports whether t is the named type typeName declared in the
// package at path.
func isNamedFrom(t types.Type, path, typeName string) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Name() != typeName {
		return false
	}
	pkg := obj.Pkg()
	return pkg != nil && pkg.Path() == path
}
