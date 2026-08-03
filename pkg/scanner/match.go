// Package scanner cross-references AST-extracted routes against the lines a
// diff actually added, and runs rules only against routes that overlap
// those added lines (rule R5: diff-aware, never a full repository scan).
package scanner

import (
	"github.com/routewarden/routewarden/pkg/ast"
	"github.com/routewarden/routewarden/pkg/output"
	"github.com/routewarden/routewarden/pkg/scanner/rules"
)

// Scan runs every registered rule against every route in routes whose line
// range overlaps addedLines, and returns the resulting findings. catalog
// may be nil, in which case no middleware is ever considered "known" (every
// unprotected mutable route in the diff will be flagged HIGH).
func Scan(file string, addedLines []int, routes []ast.RouteNode, catalog *rules.Catalog) []output.Finding {
	added := make(map[int]bool, len(addedLines))
	for _, l := range addedLines {
		added[l] = true
	}

	var findings []output.Finding
	for _, route := range routes {
		if !overlapsAddedLines(route, added) {
			continue
		}

		if f := rules.CheckMutableNoAuth(file, route, catalog); f != nil {
			findings = append(findings, *f)
		}
		if f := rules.CheckResponseLeak(file, route); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

func overlapsAddedLines(route ast.RouteNode, added map[int]bool) bool {
	for line := route.StartLine; line <= route.EndLine; line++ {
		if added[line] {
			return true
		}
	}
	return false
}
