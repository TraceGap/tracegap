package goast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
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
	name string
}

type pendingNode struct {
	node     *codegraph.FunctionNode
	pkg      string
	rawCalls []rawCall
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
			node.ExternalOps = externalOps
			node.HandlesError = handlesErr
			pending = append(pending, pendingNode{node: node, pkg: parsed.Name.Name, rawCalls: calls})

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
			name := callName(x)
			if name != "" {
				calls = append(calls, rawCall{name: name})
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

func callName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	default:
		return ""
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
