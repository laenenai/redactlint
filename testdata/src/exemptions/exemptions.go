// Package exemptions covers the opt-out marker: accepted with a reason,
// reported without one.
package exemptions

// withReasonAbove is exempt: the marker is on its own line above the field
// and states why.
type withReasonAbove struct {
	//redact:plain — the key id, not the key
	keyID string
}

// withReasonBeside is exempt: the marker is a line comment on the field.
type withReasonBeside struct {
	keyID string //redact:plain — the key id, not the key
}

// withColonAndNoDash is exempt: the separator is not part of the convention.
type withColonAndNoDash struct {
	tokenKind string //redact:plain: which kind of token, never its bytes
}

// bareMarker is reported, because an exemption nobody justified is an
// exemption nobody reviewed. The marker is a block comment here only so that
// the `want` expectation can be a second comment on the same line, which is
// where analysistest requires it.
type bareMarker struct {
	secretValue string /*redact:plain*/ // want `field secretValue is exempted by //redact:plain with no reason given`
}

// bareMarkerAbove is reported for the same reason.
type bareMarkerAbove struct {
	//redact:plain
	password string // want `field password is exempted by //redact:plain with no reason given`
}

// unrelatedComment does not exempt anything.
type unrelatedComment struct {
	token string // this is fine, honestly // want `unrelatedComment holds security-relevant material in field token`
}
