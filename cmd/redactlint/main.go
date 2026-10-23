// Command redactlint runs the redactlint analyzer over the packages named on
// the command line.
//
//	redactlint ./...
//	redactlint -patterns=key,token,pepper ./...
//
// It is a standalone binary rather than a golangci-lint plugin because
// golangci-lint's custom-linter mechanism requires rebuilding golangci-lint
// itself from a plugin module, which every repository's CI would then have to
// do before it could lint. A binary and a mise task cost one task definition
// and nothing in CI setup. See README.md.
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/laenenai/redactlint"
)

func main() { singlechecker.Main(redactlint.NewAnalyzer()) }
