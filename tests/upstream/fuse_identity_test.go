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

// Stop at the real dispatch's done callback, before transport I/O (no /dev/fuse
// or fabricated response helper). Errors must return without publishing a reply.
type dispatchReply struct{}
type plainGetattrNode struct {
	inode uint64
	err   error
}

func (n *plainGetattrNode) Attr(_ context.Context, a *fuse.Attr) error {
	a.Inode = n.inode
	return n.err
}

type getattrTestNode struct {
	identityTestNode
	inode uint64
	err   error
}

func (n *getattrTestNode) Getattr(ctx context.Context, r *fuse.GetattrRequest, s *fuse.GetattrResponse) error {
	s.Attr.Inode = n.inode
	return n.err
}
func TestGetattrDispatchInode(t *testing.T) {
	t.Setenv("SYSBOX_SYSFS_TRANSFER_HELPER", "")
	for _, custom := range []bool{false, true} {
		for _, inode := range []uint64{0, 99} {
			for _, failure := range []error{nil, fuse.EIO} {

				var node Node = &plainGetattrNode{inode: inode, err: failure}
				if custom {
					node = &getattrTestNode{inode: inode, err: failure}
				}
				server := &Server{}
				sn := &serveNode{inode: 123, node: node}
				var response *fuse.GetattrResponse
				var err error
				func() {
					defer func() {
						if p := recover(); p != nil {
							if _, ok := p.(dispatchReply); !ok {
								panic(p)
							}
						}
					}()
					err = server.handleRequest(context.Background(), node, sn, &fuse.GetattrRequest{}, func(reply interface{}) {
						response = reply.(*fuse.GetattrResponse)
						panic(dispatchReply{})
					})
				}()
				if failure != nil {
					if err != failure || response != nil {
						t.Fatalf("error dispatch: %v %+v", err, response)
					}
					continue
				}
				want := inode
				if want == 0 {
					want = 123
				}
				if err != nil || response == nil || response.Attr.Inode != want {
					t.Fatalf("custom=%v inode=%d: %v %+v", custom, inode, err, response)
				}
			}
		}
	}
}
