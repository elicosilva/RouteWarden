package ast

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

var nextRouteHandlerNames = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
}

const nextRouteQuery = `
(export_statement
  declaration: (function_declaration
    name: (identifier) @route.name)) @route.call
`

// ExtractNextJSRoutes finds exported route handler functions in a Next.js
// App Router `route.ts` file: `export async function GET(...) { ... }`,
// `export function POST(...) { ... }`, etc. Unlike Express/NestJS, the HTTP
// method is the function's name rather than an argument or decorator, and
// the route path is implied by the file's location in the App Router
// directory tree rather than encoded in the source — callers that need the
// full route path combine this with the file path already known from the
// GitHub Contents API fetch (rule R5). Route is intentionally left empty
// here.
func ExtractNextJSRoutes(idx *Index) []RouteNode {
	query, err := sitter.NewQuery([]byte(nextRouteQuery), idx.Language)
	if err != nil {
		return nil
	}
	defer query.Close()

	cursor := sitter.NewQueryCursor()
	defer cursor.Close()
	cursor.Exec(query, idx.Tree.RootNode())

	var routes []RouteNode

	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		match = cursor.FilterPredicates(match, idx.Source)

		var nameNode, callNode *sitter.Node
		for _, c := range match.Captures {
			switch query.CaptureNameForId(c.Index) {
			case "route.name":
				nameNode = c.Node
			case "route.call":
				callNode = c.Node
			}
		}

		if nameNode == nil || callNode == nil {
			continue
		}

		method := strings.ToUpper(nameNode.Content(idx.Source))
		if !nextRouteHandlerNames[method] {
			continue
		}

		var responseKeys []string
		if decl := callNode.ChildByFieldName("declaration"); decl != nil {
			body := decl.ChildByFieldName("body")
			responseKeys = ExtractResponseKeys(body, idx.Language, idx.Source)
		}

		routes = append(routes, RouteNode{
			StartLine:    int(callNode.StartPoint().Row) + 1,
			EndLine:      int(callNode.EndPoint().Row) + 1,
			Method:       method,
			ResponseKeys: responseKeys,
		})
	}

	return routes
}
