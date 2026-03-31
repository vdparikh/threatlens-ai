package analyze

import (
	"fmt"
	"strings"
)

// FlowGraphToMermaid renders a Mermaid flowchart (LR) for documentation / webviews.
func FlowGraphToMermaid(g *FlowGraph) string {
	if g == nil || len(g.Nodes) == 0 {
		return "flowchart LR\n  empty[No graph data]"
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	shape := func(kind FlowNodeKind, id, label string) string {
		esc := mermaidEscape(label)
		switch kind {
		case KindActor:
			return fmt.Sprintf("    %s([%s])\n", id, esc)
		case KindData:
			return fmt.Sprintf("    %s[(%s)]\n", id, esc)
		case KindExternal:
			return fmt.Sprintf("    %s{{%s}}\n", id, esc)
		default:
			return fmt.Sprintf("    %s[%s]\n", id, esc)
		}
	}
	for _, n := range g.Nodes {
		b.WriteString(shape(n.Kind, n.ID, n.Label))
	}
	for _, e := range g.Edges {
		lbl := ""
		if e.Label != "" {
			lbl = "|" + mermaidEscape(e.Label) + "|"
		}
		b.WriteString(fmt.Sprintf("    %s -->%s %s\n", e.From, lbl, e.To))
	}
	return strings.TrimSpace(b.String())
}

func mermaidEscape(s string) string {
	s = strings.ReplaceAll(s, `"`, "#quot;")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}
