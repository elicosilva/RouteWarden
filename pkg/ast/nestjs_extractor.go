package ast

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

var nestHTTPDecorators = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true,
}

// ExtractNestJSRoutes walks idx's tree looking for NestJS controller
// classes (@Controller(...)) and extracts one RouteNode per HTTP method
// decorator (@Get/@Post/@Put/@Delete/@Patch) found on a method. Route paths
// combine the controller's base path with the method decorator's path
// argument, matching NestJS's own routing behavior. @UseGuards(...)
// arguments are reported as Middlewares (rule R4: Clerk/Supabase/Auth0/
// NextAuth guards are just identifiers here — pkg/scanner/rules/catalog.go
// decides which ones count as real auth).
func ExtractNestJSRoutes(idx *Index) []RouteNode {
	var routes []RouteNode

	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		if node == nil {
			return
		}
		if node.Type() == "class_declaration" {
			routes = append(routes, extractControllerRoutes(node, idx.Language, idx.Source)...)
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(idx.Tree.RootNode())

	return routes
}

func extractControllerRoutes(classNode *sitter.Node, lang *sitter.Language, source []byte) []RouteNode {
	basePath, isController := controllerBasePath(classNode, source)
	if !isController {
		return nil
	}

	body := classNode.ChildByFieldName("body")
	if body == nil {
		return nil
	}

	var routes []RouteNode
	var pendingDecorators []*sitter.Node

	count := int(body.NamedChildCount())
	for i := 0; i < count; i++ {
		child := body.NamedChild(i)
		switch child.Type() {
		case "decorator":
			pendingDecorators = append(pendingDecorators, child)
		case "method_definition":
			if route, ok := methodRoute(child, pendingDecorators, basePath, lang, source); ok {
				routes = append(routes, route)
			}
			pendingDecorators = nil
		default:
			// Properties, constructors, etc: not a route. Clear any
			// dangling decorators (e.g. @Injectable on a field) so they
			// don't leak onto the next method.
			pendingDecorators = nil
		}
	}

	return routes
}

// controllerBasePath returns the string argument of @Controller(...) and
// true if classNode is decorated with @Controller at all (with or without
// an explicit path argument). The decorator may be a field of the class
// itself or, when the class is directly exported, a field of the
// surrounding export_statement.
func controllerBasePath(classNode *sitter.Node, source []byte) (string, bool) {
	var decorators []*sitter.Node

	if d := classNode.ChildByFieldName("decorator"); d != nil {
		decorators = append(decorators, d)
	}
	if parent := classNode.Parent(); parent != nil && parent.Type() == "export_statement" {
		if d := parent.ChildByFieldName("decorator"); d != nil {
			decorators = append(decorators, d)
		}
	}

	for _, dec := range decorators {
		name, argsNode := decoratorCallParts(dec, source)
		if name == "Controller" {
			return firstStringArg(argsNode, source), true
		}
	}

	return "", false
}

// methodRoute inspects a method_definition's preceding decorators for an
// HTTP method decorator (@Get/@Post/etc.) and, if found, builds a RouteNode.
// Methods with no HTTP decorator (helpers, lifecycle hooks, etc.) return
// ok=false and are not reported as routes.
func methodRoute(method *sitter.Node, decorators []*sitter.Node, basePath string, lang *sitter.Language, source []byte) (RouteNode, bool) {
	var httpMethod, subPath string
	var middlewares []string
	found := false

	for _, dec := range decorators {
		name, argsNode := decoratorCallParts(dec, source)
		switch {
		case nestHTTPDecorators[name]:
			httpMethod = strings.ToUpper(name)
			subPath = firstStringArg(argsNode, source)
			found = true
		case name == "UseGuards":
			middlewares = append(middlewares, decoratorArgIdentifiers(argsNode, source)...)
		}
	}

	if !found {
		return RouteNode{}, false
	}

	responseKeys := ExtractResponseKeys(method.ChildByFieldName("body"), lang, source)

	return RouteNode{
		StartLine:    int(method.StartPoint().Row) + 1,
		EndLine:      int(method.EndPoint().Row) + 1,
		Method:       httpMethod,
		Route:        joinRoutePath(basePath, subPath),
		Middlewares:  middlewares,
		ResponseKeys: responseKeys,
	}, true
}

// decoratorCallParts extracts a decorator's name (e.g. "Controller",
// "UseGuards", "Get") and, if it was called with arguments (@Foo(...)
// rather than bare @Foo), the arguments node.
func decoratorCallParts(dec *sitter.Node, source []byte) (name string, argsNode *sitter.Node) {
	for i := 0; i < int(dec.NamedChildCount()); i++ {
		c := dec.NamedChild(i)
		switch c.Type() {
		case "call_expression":
			if fn := c.ChildByFieldName("function"); fn != nil {
				name = fn.Content(source)
			}
			argsNode = c.ChildByFieldName("arguments")
			return
		case "identifier":
			return c.Content(source), nil
		}
	}
	return "", nil
}

func firstStringArg(argsNode *sitter.Node, source []byte) string {
	if argsNode == nil {
		return ""
	}
	for i := 0; i < int(argsNode.NamedChildCount()); i++ {
		c := argsNode.NamedChild(i)
		if c.Type() == "string" {
			return stripQuotes(c.Content(source))
		}
	}
	return ""
}

func decoratorArgIdentifiers(argsNode *sitter.Node, source []byte) []string {
	if argsNode == nil {
		return nil
	}
	var out []string
	for i := 0; i < int(argsNode.NamedChildCount()); i++ {
		c := argsNode.NamedChild(i)
		if c.Type() == "identifier" || c.Type() == "member_expression" {
			out = append(out, c.Content(source))
		}
	}
	return out
}

func joinRoutePath(base, sub string) string {
	base = strings.Trim(base, "/")
	sub = strings.Trim(sub, "/")
	switch {
	case base == "" && sub == "":
		return "/"
	case base == "":
		return "/" + sub
	case sub == "":
		return "/" + base
	default:
		return "/" + base + "/" + sub
	}
}
