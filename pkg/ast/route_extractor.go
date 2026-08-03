package ast

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// RouteNode describes a single route definition found in an Express-style
// router/app (router.get/post/put/delete/patch(...)). NestJS decorator
// routes and Next.js API route handlers use different AST shapes; see
// nestjs_extractor.go and nextjs_extractor.go.
type RouteNode struct {
	StartLine    int      // 1-indexed line where the route call begins
	EndLine      int      // 1-indexed line where the route call ends
	Method       string   // HTTP method, uppercased: GET, POST, PUT, DELETE, PATCH
	Route        string   // route path literal, e.g. "/users"
	Middlewares  []string // identifiers/member expressions passed as middleware args
	ResponseKeys []string // object-literal keys seen in res.json/res.send calls
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
}

// expressRouteQuery matches calls like `router.post("/users", auth, handler)`
// or `app.get("/health", handler)`. It captures the method name, the full
// call, and the arguments list.
const expressRouteQuery = `
(call_expression
  function: (member_expression
    object: (identifier)
    property: (property_identifier) @route.method)
  arguments: (arguments) @route.args) @route.call
`

// ExtractExpressRoutes walks idx's tree and returns every Express-style
// route definition it finds. Rule R4 scopes this to the known HTTP method
// names in httpMethods; any other member-expression call (e.g. `app.use`,
// `router.param`, `console.log`) is silently skipped.
func ExtractExpressRoutes(idx *Index) ([]RouteNode, error) {
	query, err := sitter.NewQuery([]byte(expressRouteQuery), idx.Language)
	if err != nil {
		return nil, fmt.Errorf("ast: compile express route query: %w", err)
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

		var methodNode, argsNode, callNode *sitter.Node
		for _, c := range match.Captures {
			switch query.CaptureNameForId(c.Index) {
			case "route.method":
				methodNode = c.Node
			case "route.args":
				argsNode = c.Node
			case "route.call":
				callNode = c.Node
			}
		}

		if methodNode == nil || argsNode == nil || callNode == nil {
			continue
		}

		method := strings.ToLower(methodNode.Content(idx.Source))
		if !httpMethods[method] {
			continue
		}

		route, middlewares := parseRouteArgs(argsNode, idx.Source)
		responseKeys := ExtractResponseKeys(argsNode, idx.Language, idx.Source)

		routes = append(routes, RouteNode{
			StartLine:    int(callNode.StartPoint().Row) + 1,
			EndLine:      int(callNode.EndPoint().Row) + 1,
			Method:       strings.ToUpper(method),
			Route:        route,
			Middlewares:  middlewares,
			ResponseKeys: responseKeys,
		})
	}

	return routes, nil
}

// parseRouteArgs reads an Express route call's argument list. The first
// string literal argument is treated as the route path. Every identifier,
// member-expression, or call-expression argument that appears before the
// final argument is treated as middleware; the final argument is assumed to
// be the request handler and is not reported as middleware.
func parseRouteArgs(argsNode *sitter.Node, source []byte) (route string, middlewares []string) {
	count := int(argsNode.NamedChildCount())

	for i := 0; i < count; i++ {
		child := argsNode.NamedChild(i)
		switch child.Type() {
		case "string":
			if route == "" {
				route = stripQuotes(child.Content(source))
			}
		case "identifier", "member_expression", "call_expression":
			// The final argument is assumed to be the handler, not middleware.
			if i < count-1 {
				middlewares = append(middlewares, child.Content(source))
			}
		}
	}

	return route, middlewares
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') || (first == '`' && last == '`') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
