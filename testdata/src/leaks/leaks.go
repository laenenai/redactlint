// Package leaks holds the shapes that must be reported. Each one is a real
// type from the laenen-ai modules as it stood before the convention landed,
// reduced to the field that mattered.
package leaks

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// localConfig is keyring's local.Config: the deployment root key in a field
// with no rendering method anywhere on the type. fmt.Sprintf("%v", cfg)
// printed the key's bytes and json.Marshal emitted them as base64.
type localConfig struct {
	rootKey     []byte // want `localConfig holds security-relevant material in field rootKey, but does not implement fmt\.Stringer .* or fmt\.Formatter .* or json\.Marshaler .* or slog\.LogValuer`
	rootKeyFile string // want `localConfig holds security-relevant material in field rootKeyFile`
	storeName   string
}

// transitConfig is keyring's openbaotransit.Config: String and LogValue were
// present and a doc comment said the token must never be logged, and %#v,
// %d and json.Marshal printed it anyway.
type transitConfig struct {
	address string
	token   string // want `transitConfig holds security-relevant material in field token, but does not implement fmt\.Formatter .* or json\.Marshaler`
}

func (c transitConfig) String() string       { return "transitConfig(redacted)" }
func (c transitConfig) LogValue() slog.Value { return slog.StringValue("transitConfig(redacted)") }

// dek is keyring's domain.DEK before Format existed: five interfaces, and %d
// still printed all 32 key bytes, because %d consults none of them.
type dek struct {
	material []byte // want `dek holds security-relevant material in field material, but does not implement fmt\.Formatter`
}

func (k dek) String() string               { return "dek(redacted)" }
func (k dek) GoString() string             { return "dek(redacted)" }
func (k dek) MarshalJSON() ([]byte, error) { return json.Marshal("dek(redacted)") }
func (k dek) LogValue() slog.Value         { return slog.StringValue("dek(redacted)") }

// namedOverString proves the "or a named type over either" half of the rule:
// a DSN is a named string, and the field holding one is still material.
type dsn string

type scoped struct {
	metadataDSN dsn // want `scoped holds security-relevant material in field metadataDSN`
	appRole     string
}

// wrongSignatures has all four method names and none of the four signatures,
// which must not count. A String() error is not fmt.Stringer.
type wrongSignatures struct {
	secretValue string // want `wrongSignatures holds security-relevant material in field secretValue, but does not implement fmt\.Stringer .* or fmt\.Formatter .* or json\.Marshaler .* or slog\.LogValuer`
}

func (w wrongSignatures) String() error                { return nil }
func (w wrongSignatures) Format(_ fmt.State)           {}
func (w wrongSignatures) MarshalJSON() (string, error) { return "", nil }
func (w wrongSignatures) LogValue() string             { return "" }

// severalOnOneLine reports each name on a shared field declaration.
type severalOnOneLine struct {
	tokenA, tokenB string // want `severalOnOneLine holds security-relevant material in fields tokenA, tokenB`
}
