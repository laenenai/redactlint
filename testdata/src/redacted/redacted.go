// Package redacted holds the shapes that must NOT be reported: types that
// satisfy the convention, and field names and types that are not material.
package redacted

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

const placeholder = "redacted"

// allFour is the convention satisfied: one fixed placeholder through every
// rendering, naming the type and carrying neither the material nor its
// length.
type allFour struct {
	rootKey []byte
}

func (c allFour) String() string               { return "redacted.allFour(" + placeholder + ")" }
func (c allFour) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, c.String()) }
func (c allFour) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }
func (c allFour) LogValue() slog.Value         { return slog.StringValue(c.String()) }

// pointerReceivers is the right shape for a type holding a lock: a value
// receiver would copy it, so the methods are on the pointer, and a consumer
// holds the pointer anyway.
type pointerReceivers struct {
	wrapKey []byte
}

func (m *pointerReceivers) String() string               { return placeholder }
func (m *pointerReceivers) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, placeholder) }
func (m *pointerReceivers) MarshalJSON() ([]byte, error) { return json.Marshal(placeholder) }
func (m *pointerReceivers) LogValue() slog.Value         { return slog.StringValue(placeholder) }

// exportedFields are not flagged. An exported field of a redacting type is
// already covered, because fmt consults an exported field's own methods; an
// exported plain field belongs to whoever renders the struct.
type exportedFields struct {
	RootKey  []byte
	Password string
	DSN      string
}

// notMaterialTypes: the field names match, the types are not string or
// []byte, so there is nothing this analyzer can claim to recognize.
type notMaterialTypes struct {
	keyVersion   uint32
	keyCount     int
	digest       [32]byte
	keyRotation  func()
	keyParts     []string
	keyByPointer *string
}

// innocentNames do not match any pattern.
type innocentNames struct {
	name   string
	region string
	body   []byte
}
