package codegraph

import "sort"

type FunctionID string

type ExternalSignals struct {
	HTTP    bool
	DB      bool
	RPC     bool
	Queue   bool
	Count   int
	Reasons []string
}

type FunctionNode struct {
	ID            FunctionID
	Package       string
	FilePath      string
	FuncName      string
	Receiver      string
	QualifiedName string
	StartLine     int
	EndLine       int

	LocalCalls      []FunctionID
	UnresolvedCalls []string

	StartsSpan   bool
	IsHTTPHandler bool
	ExternalOps  ExternalSignals
	HandlesError bool
}

type Graph struct {
	Functions map[FunctionID]*FunctionNode
	ByName    map[string][]FunctionID
	ByFile    map[string][]FunctionID
}

func (g *Graph) SortedIDs() []FunctionID {
	ids := make([]FunctionID, 0, len(g.Functions))
	for id := range g.Functions {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
