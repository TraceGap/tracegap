package goast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"sort"
	"strings"

	"tracegap/internal/codegraph"
)

const (
	DefaultMaxFiles    = 5000
	DefaultMaxFileSize = 1 << 20
)

type Options struct {
	MaxFiles    int
	MaxFileSize int64
}

func DefaultOptions() Options {
	return Options{MaxFiles: DefaultMaxFiles, MaxFileSize: DefaultMaxFileSize}
}

type rawCall struct {
	name         string
	packageHint  string
}

type pendingNode struct {
	node       *codegraph.FunctionNode
	pkg        string
	rawCalls   []rawCall
	importPkgs map[string]string
}

func BuildGraph(repoPath string, opts Options) (*codegraph.Graph, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = DefaultMaxFiles
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}

	goFiles, err := collectGoFiles(repoPath, opts)
	if err != nil {
		return nil, err
	}

	graph := &codegraph.Graph{
		Functions: make(map[codegraph.FunctionID]*codegraph.FunctionNode),
		ByName:    make(map[string][]codegraph.FunctionID),
		ByFile:    make(map[string][]codegraph.FunctionID),
	}

	fset := token.NewFileSet()
	pending := make([]pendingNode, 0, 64)
	pkgNameIndex := make(map[string]map[string][]codegraph.FunctionID)

	for _, filePath := range goFiles {
		parsed, err := parser.ParseFile(fset, filePath, nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}

		rel, err := filepath.Rel(repoPath, filePath)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		imports := importAliases(parsed.Imports)
		routeHints := collectRouteHints(parsed)

		for _, decl := range parsed.Decls {
			fnDecl, ok := decl.(*ast.FuncDecl)
			if !ok || fnDecl.Name == nil {
				continue
			}
			fnName := fnDecl.Name.Name
			receiver := receiverName(fnDecl)
			qualified := qualify(parsed.Name.Name, receiver, fnName)
			id := codegraph.FunctionID(rel + "::" + qualified)
			start := fset.Position(fnDecl.Pos()).Line
			end := fset.Position(fnDecl.End()).Line

			node := &codegraph.FunctionNode{
				ID:            id,
				Package:       parsed.Name.Name,
				FilePath:      rel,
				FuncName:      fnName,
				Receiver:      receiver,
				QualifiedName: qualified,
				StartLine:     start,
				EndLine:       end,
			}
			calls, startsSpan, externalOps, handlesErr := analyzeBody(fnDecl, imports)
			node.StartsSpan = startsSpan
			node.IsHTTPHandler = isHTTPHandlerSignature(fnDecl, imports)
			node.RouteTokens = append(node.RouteTokens, routeHints[fnName]...)
			node.RouteTokens = dedupeStrings(node.RouteTokens)
			node.ExternalOps = externalOps
			node.HandlesError = handlesErr
			pending = append(pending, pendingNode{node: node, pkg: parsed.Name.Name, rawCalls: calls, importPkgs: imports})

			graph.Functions[id] = node
			graph.ByName[fnName] = append(graph.ByName[fnName], id)
			graph.ByFile[rel] = append(graph.ByFile[rel], id)

			if _, ok := pkgNameIndex[parsed.Name.Name]; !ok {
				pkgNameIndex[parsed.Name.Name] = make(map[string][]codegraph.FunctionID)
			}
			pkgNameIndex[parsed.Name.Name][fnName] = append(pkgNameIndex[parsed.Name.Name][fnName], id)
		}
	}

	for _, item := range pending {
		seen := make(map[codegraph.FunctionID]struct{})
		for _, rc := range item.rawCalls {
			resolved := pkgNameIndex[item.pkg][rc.name]
			if len(resolved) == 0 && rc.packageHint != "" {
				resolved = pkgNameIndex[rc.packageHint][rc.name]
			}
			if len(resolved) == 0 {
				item.node.UnresolvedCalls = append(item.node.UnresolvedCalls, rc.name)
				continue
			}
			for _, id := range resolved {
				if id == item.node.ID {
					continue
				}
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				item.node.LocalCalls = append(item.node.LocalCalls, id)
			}
		}
		sort.Slice(item.node.LocalCalls, func(i, j int) bool { return item.node.LocalCalls[i] < item.node.LocalCalls[j] })
		sort.Strings(item.node.UnresolvedCalls)
	}

	return graph, nil
}

func collectGoFiles(repoPath string, opts Options) ([]string, error) {
	files := make([]string, 0, 256)
	count := 0

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		count++
		if count > opts.MaxFiles {
			return fmt.Errorf("file scan limit reached (%d)", opts.MaxFiles)
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		if info.Size() > opts.MaxFileSize {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func shouldSkipDir(name string) bool {
	switch strings.TrimSpace(name) {
	case ".git", "vendor", "node_modules", "dist", "build", "tmp":
		return true
	default:
		return false
	}
}

func qualify(pkg, receiver, fn string) string {
	if receiver == "" {
		return pkg + "." + fn
	}
	return pkg + ".(*" + receiver + ")." + fn
}

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	switch expr := fn.Recv.List[0].Type.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

func importAliases(imports []*ast.ImportSpec) map[string]string {
	out := make(map[string]string, len(imports))
	for _, spec := range imports {
		path := strings.Trim(spec.Path.Value, "\"")
		alias := ""
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "" {
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
		}
		out[alias] = path
	}
	return out
}

func collectRouteHints(file *ast.File) map[string][]string {
	out := make(map[string][]string)
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		handler, path, ok := parseRouteRegistration(call)
		if !ok {
			return true
		}
		toks := routePathTokens(path)
		if len(toks) == 0 {
			return true
		}
		out[handler] = append(out[handler], toks...)
		out[handler] = dedupeStrings(out[handler])
		return true
	})
	return out
}

func parseRouteRegistration(call *ast.CallExpr) (handlerName, routePath string, ok bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return "", "", false
	}
	m := strings.ToLower(strings.TrimSpace(sel.Sel.Name))
	if !isRouteRegistrationMethod(m) {
		return "", "", false
	}
	if len(call.Args) < 2 {
		return "", "", false
	}
	pathLit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || pathLit.Kind != token.STRING {
		return "", "", false
	}
	path, err := strconv.Unquote(pathLit.Value)
	if err != nil {
		path = strings.Trim(pathLit.Value, "\"")
	}
	handler := handlerExprName(call.Args[1])
	if handler == "" || strings.TrimSpace(path) == "" {
		return "", "", false
	}
	return handler, path, true
}

func isRouteRegistrationMethod(method string) bool {
	switch method {
	case "handlefunc", "handle", "get", "post", "put", "delete", "patch", "options", "head":
		return true
	default:
		return false
	}
}

func handlerExprName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return strings.TrimSpace(v.Name)
	case *ast.SelectorExpr:
		if v.Sel != nil {
			return strings.TrimSpace(v.Sel.Name)
		}
	}
	return ""
}

func routePathTokens(path string) []string {
	clean := strings.TrimSpace(strings.ToLower(path))
	if clean == "" {
		return nil
	}
	repl := strings.NewReplacer("/", " ", "-", " ", "_", " ", "{", " ", "}", " ", ":", " ")
	clean = repl.Replace(clean)
	parts := strings.Fields(clean)
	return dedupeStrings(parts)
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func isHTTPHandlerSignature(fn *ast.FuncDecl, imports map[string]string) bool {
	if fn == nil || fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	hasWriter := false
	hasRequest := false
	for _, field := range fn.Type.Params.List {
		if field == nil || field.Type == nil {
			continue
		}
		if isResponseWriterType(field.Type, imports) {
			hasWriter = true
		}
		if isRequestPointerType(field.Type, imports) {
			hasRequest = true
		}
	}
	return hasWriter && hasRequest
}

func isResponseWriterType(expr ast.Expr, imports map[string]string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "ResponseWriter" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if ident.Name == "http" {
		return true
	}
	return imports[ident.Name] == "net/http"
}

func isRequestPointerType(expr ast.Expr, imports map[string]string) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Request" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if ident.Name == "http" {
		return true
	}
	return imports[ident.Name] == "net/http"
}

func analyzeBody(fn *ast.FuncDecl, imports map[string]string) ([]rawCall, bool, codegraph.ExternalSignals, bool) {
	calls := make([]rawCall, 0, 8)
	startsSpan := false
	external := codegraph.ExternalSignals{Reasons: make([]string, 0, 4)}
	handlesErr := false

	addReason := func(reason string) {
		for _, existing := range external.Reasons {
			if existing == reason {
				return
			}
		}
		external.Reasons = append(external.Reasons, reason)
		external.Count = len(external.Reasons)
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			rc := callRef(x, imports)
			if rc.name != "" {
				calls = append(calls, rc)
			}
			if isSpanStartCall(x) {
				startsSpan = true
			}
			if reason, ok := detectHTTPCall(x, imports); ok {
				external.HTTP = true
				addReason(reason)
			}
			if reason, ok := detectDBCall(x); ok {
				external.DB = true
				addReason(reason)
			}
			if reason, ok := detectQueueCall(x); ok {
				external.Queue = true
				addReason(reason)
			}
			if reason, ok := detectRPCCall(x, imports); ok {
				external.RPC = true
				addReason(reason)
			}
		case *ast.IfStmt:
			if isErrCondition(x.Cond) {
				handlesErr = true
			}
		case *ast.ReturnStmt:
			if hasErrResult(x.Results) {
				handlesErr = true
			}
		}
		return true
	})

	sort.Strings(external.Reasons)
	return calls, startsSpan, external, handlesErr
}

func callRef(call *ast.CallExpr, imports map[string]string) rawCall {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return rawCall{name: fun.Name}
	case *ast.SelectorExpr:
		out := rawCall{name: fun.Sel.Name}
		if ident, ok := fun.X.(*ast.Ident); ok {
			if importPath, imported := imports[ident.Name]; imported {
				parts := strings.Split(importPath, "/")
				if len(parts) > 0 {
					out.packageHint = parts[len(parts)-1]
				}
			}
		}
		return out
	default:
		return rawCall{}
	}
}

func isSpanStartCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Start" {
		return false
	}
	if ident, ok := sel.X.(*ast.Ident); ok && strings.Contains(strings.ToLower(ident.Name), "tracer") {
		return true
	}
	if tracerCall, ok := sel.X.(*ast.CallExpr); ok {
		if tracerSel, ok := tracerCall.Fun.(*ast.SelectorExpr); ok && tracerSel.Sel != nil && tracerSel.Sel.Name == "Tracer" {
			return true
		}
	}
	if len(call.Args) > 0 {
		if arg, ok := call.Args[0].(*ast.Ident); ok && strings.Contains(strings.ToLower(arg.Name), "ctx") {
			return true
		}
	}
	return false
}

func detectHTTPCall(call *ast.CallExpr, imports map[string]string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return "", false
	}
	method := sel.Sel.Name
	if method == "Do" {
		return "Do", true
	}
	if method != "Get" && method != "Post" {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	alias := ident.Name
	if alias == "http" {
		return "http." + method, true
	}
	if imports[alias] == "net/http" {
		return alias + "." + method, true
	}
	return "", false
}

func detectDBCall(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return "", false
	}
	switch sel.Sel.Name {
	case "QueryContext", "ExecContext", "QueryRowContext":
		return sel.Sel.Name, true
	default:
		return "", false
	}
}

func detectQueueCall(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return "", false
	}
	switch sel.Sel.Name {
	case "Publish", "Send", "Produce", "Enqueue":
		return sel.Sel.Name, true
	default:
		return "", false
	}
}

func detectRPCCall(call *ast.CallExpr, imports map[string]string) (string, bool) {
	hasGRPC := false
	for _, path := range imports {
		if strings.Contains(path, "grpc") {
			hasGRPC = true
			break
		}
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		if hasGRPC {
			if ident, ok := call.Fun.(*ast.Ident); ok && strings.Contains(strings.ToLower(ident.Name), "client") {
				return ident.Name, true
			}
		}
		return "", false
	}

	if ident, ok := sel.X.(*ast.Ident); ok {
		if strings.Contains(ident.Name, "Client") || strings.Contains(strings.ToLower(ident.Name), "client") {
			return ident.Name + "." + sel.Sel.Name, true
		}
	}
	if hasGRPC {
		return sel.Sel.Name, true
	}
	return "", false
}

func isErrCondition(expr ast.Expr) bool {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op.String() != "!=" {
		return false
	}
	left, leftOK := bin.X.(*ast.Ident)
	right, rightOK := bin.Y.(*ast.Ident)
	if leftOK && rightOK {
		return (left.Name == "err" && right.Name == "nil") || (left.Name == "nil" && right.Name == "err")
	}
	return false
}

func hasErrResult(results []ast.Expr) bool {
	for _, res := range results {
		if ident, ok := res.(*ast.Ident); ok && ident.Name == "err" {
			return true
		}
		if call, ok := res.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "Errorf" {
				return true
			}
		}
	}
	return false
}
