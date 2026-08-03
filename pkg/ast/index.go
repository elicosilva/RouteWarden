// Package ast wraps tree-sitter to parse Express/NestJS/Next.js
// TypeScript/JavaScript source into a syntax tree, and provides route
// extraction so pkg/scanner can cross-reference findings against
// diff-added lines (rule R5).
package ast

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// Index holds a parsed syntax tree together with the original source, so
// callers can slice out node text and compute line numbers.
type Index struct {
	Tree     *sitter.Tree
	Source   []byte
	Language *sitter.Language
}

// LanguageForPath picks a tree-sitter grammar based on file extension.
// RouteWarden only supports Express/NestJS/Next.js TS/JS sources (rule R4).
func LanguageForPath(path string) (*sitter.Language, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".tsx":
		return typescript.GetLanguage(), nil
	case ".js", ".jsx", ".mjs", ".cjs":
		return javascript.GetLanguage(), nil
	default:
		return nil, fmt.Errorf("ast: unsupported file extension for %q (expected .ts/.tsx/.js/.jsx)", path)
	}
}

// Parse builds a syntax tree for source, selecting the grammar based on the
// file's extension (path is only used to pick the grammar, the file itself
// is never read from disk here — source always comes from pkg/github).
func Parse(path string, source []byte) (*Index, error) {
	lang, err := LanguageForPath(path)
	if err != nil {
		return nil, err
	}

	parser := sitter.NewParser()
	parser.SetLanguage(lang)

	tree, err := parser.ParseCtx(context.Background(), nil, source)
	if err != nil {
		return nil, fmt.Errorf("ast: parse %q: %w", path, err)
	}

	return &Index{Tree: tree, Source: source, Language: lang}, nil
}
