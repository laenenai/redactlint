// Package patterns is run with -patterns=pepper,seal, to prove the list is
// configurable: the default vocabulary must not fire, and the configured one
// must.
package patterns

// configuredPattern is flagged because "pepper" is in the configured list.
type configuredPattern struct {
	pepperValue []byte // want `configuredPattern holds security-relevant material in field pepperValue`
}

// defaultPatternNotConfigured is not flagged: "token" is in the default list
// and not in the configured one.
type defaultPatternNotConfigured struct {
	token string
}
