package hub

import (
	"sort"

	"github.com/mahantsunandan/locnet/internal/netmap"
)

func sortNodes(n []Node) {
	sort.Slice(n, func(i, j int) bool { return n[i].Name < n[j].Name })
}

func sortNetmapNodes(n []netmap.Node) {
	sort.Slice(n, func(i, j int) bool { return n[i].Name < n[j].Name })
}

func sortTokens(t []JoinToken) {
	sort.Slice(t, func(i, j int) bool { return t[i].CreatedAt.After(t[j].CreatedAt) })
}
