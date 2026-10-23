// Package testfiles proves that _test.go files are skipped by default while
// the package's shipped files are not.
package testfiles

// shipped is in an ordinary file and is reported.
type shipped struct {
	rootKey []byte // want `shipped holds security-relevant material in field rootKey`
}
