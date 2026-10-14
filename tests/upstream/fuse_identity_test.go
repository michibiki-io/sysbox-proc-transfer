package fs

import (
	"bazil.org/fuse"
	"context"
	"os"
	"testing"
)

type identityTestNode struct {
	identity Node
	size     uint64
}

func (n *identityTestNode) Attr(_ context.Context, a *fuse.Attr) error {
	a.Inode = 77
	a.Mode = os.FileMode(0444)
	a.Size = n.size
	return nil
}
func (n *identityTestNode) LookupIdentityNode() Node { return n.identity }
func TestLookupIdentityFreshAttributes(t *testing.T) {
	base := &identityTestNode{size: 1}
	base.identity = base
	server := &Server{nodeRef: make(map[Node]fuse.NodeID), node: []*serveNode{nil}}
	parent := &serveNode{inode: 1}
	var first fuse.LookupResponse
	if err := server.saveLookup(context.Background(), &first, parent, "file", base); err != nil {
		t.Fatal(err)
	}
	for _, size := range []uint64{21, 32} {
		fresh := &identityTestNode{identity: base, size: size}
		var response fuse.LookupResponse
		if err := server.saveLookup(context.Background(), &response, parent, "file", fresh); err != nil {
			t.Fatal(err)
		}
		if response.Node != first.Node || response.Generation != first.Generation || response.Attr.Size != size {
			t.Fatalf("identity or fresh attributes lost: %+v", response)
		}
	}
	if len(server.nodeRef) != 1 || len(server.node) != 2 {
		t.Fatal("fresh lookup object retained as cached data")
	}
}
