// Package testfilesincluded is testfiles again, run with -include-tests, so
// the fixture in its _test.go file is reported too.
package testfilesincluded

type shipped struct {
	rootKey []byte // want `shipped holds security-relevant material in field rootKey`
}
