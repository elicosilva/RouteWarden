package ast

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const responseCallQuery = `
(call_expression
  function: (member_expression
    property: (property_identifier) @resp.method)
  arguments: (arguments (object) @resp.payload)) @resp.call
`

// ExtractResponseKeys scans scopeNode's subtree for response calls
// (`*.json({...})` or `*.send({...})`, matching Express's `res`, NestJS's
// implicit response object, and Next.js's `NextResponse`) and collects
// every object-literal key passed to them. It does not inspect values —
// RouteWarden only reads source text, never executes anything (rule R7).
// A nil or malformed scopeNode returns no keys rather than erroring, since
// this is a best-effort signal for the MEDIUM response_leak rule, not a
// required part of route extraction.
func ExtractResponseKeys(scopeNode *sitter.Node, lang *sitter.Language, source []byte) []string {
	if scopeNode == nil || lang == nil {
		return nil
	}

	query, err := sitter.NewQuery([]byte(responseCallQuery), lang)
	if err != nil {
		return nil
	}
	defer query.Close()

	cursor := sitter.NewQueryCursor()
	defer cursor.Close()
	cursor.Exec(query, scopeNode)

	var keys []string
	seen := make(map[string]bool)

	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		match = cursor.FilterPredicates(match, source)

		var methodNode, payloadNode *sitter.Node
		for _, c := range match.Captures {
			switch query.CaptureNameForId(c.Index) {
			case "resp.method":
				methodNode = c.Node
			case "resp.payload":
				payloadNode = c.Node
			}
		}
		if methodNode == nil || payloadNode == nil {
			continue
		}

		method := strings.ToLower(methodNode.Content(source))
		if method != "json" && method != "send" {
			continue
		}

		for _, k := range collectObjectKeys(payloadNode, source) {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}

	return keys
}

// collectObjectKeys recursively walks an object literal (including nested
// objects) and returns every key it finds, in the order encountered.
func collectObjectKeys(node *sitter.Node, source []byte) []string {
	var keys []string

	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if n.Type() == "pair" {
			if keyNode := n.ChildByFieldName("key"); keyNode != nil {
				keys = append(keys, keyText(keyNode, source))
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(node)

	return keys
}

func keyText(keyNode *sitter.Node, source []byte) string {
	if keyNode.Type() == "string" {
		return stripQuotes(keyNode.Content(source))
	}
	return keyNode.Content(source)
}
