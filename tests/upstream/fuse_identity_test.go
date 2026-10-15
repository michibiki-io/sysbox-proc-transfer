package fs

import (
	"bazil.org/fuse"
	"bytes"
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

// The network stream is live, not a cached cross-request snapshot. Exercise the
// real dispatch: stable continuation and rewind have different guarantees.
type liveDirHandle struct {
	uncached bool
	calls    int
}

func (h *liveDirHandle) ReadDirAllUncached() bool { return h.uncached }
func (h *liveDirHandle) ReadDirAll(_ context.Context, r *fuse.ReadRequest) ([]fuse.Dirent, error) {
	h.calls++
	switch r.Pid {
	case 1:
		return []fuse.Dirent{{Inode: 11, Name: "a", Type: fuse.DT_Dir}, {Inode: 12, Name: "outer-secret", Type: fuse.DT_Dir}}, nil
	case 2:
		return []fuse.Dirent{{Inode: 13, Name: "inside", Type: fuse.DT_Dir}}, nil
	default:
		return nil, fuse.EIO
	}
}
func TestNetworkReadDirDispatch(t *testing.T) {
	for _, uncached := range []bool{false, true} {
		h := &liveDirHandle{uncached: uncached}
		server := &Server{}
		id := server.saveHandle(h)
		node := &plainGetattrNode{inode: 77}
		sn := &serveNode{inode: 77, node: node}
		read := func(pid uint32, offset int64, size int) ([]byte, error) {
			var data []byte
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil {
						if _, ok := p.(dispatchReply); !ok {
							panic(p)
						}
					}
				}()
				err = server.handleRequest(context.Background(), node, sn, &fuse.ReadRequest{Header: fuse.Header{Pid: pid}, Handle: id, Dir: true, Offset: offset, Size: size}, func(reply interface{}) {
					data = append([]byte{}, reply.(*fuse.ReadResponse).Data...)
					panic(dispatchReply{})
				})
			}()
			return data, err
		}
		first := fuse.AppendDirent(nil, fuse.Dirent{Inode: 11, Name: "a", Type: fuse.DT_Dir})
		old := fuse.AppendDirent(append([]byte{}, first...), fuse.Dirent{Inode: 12, Name: "outer-secret", Type: fuse.DT_Dir})
		fresh := fuse.AppendDirent(nil, fuse.Dirent{Inode: 13, Name: "inside", Type: fuse.DT_Dir})
		data, err := read(1, 0, len(first))
		if err != nil || !bytes.Equal(data, first) {
			t.Fatalf("initial response: %v %x", err, data)
		}
		data, err = read(1, int64(len(first)), 4096)
		if err != nil || !bytes.Equal(data, old[len(first):]) {
			t.Fatalf("stable continuation: %v %x", err, data)
		}
		data, err = read(2, int64(len(first)), 4096)
		if err != nil {
			t.Fatal(err)
		}
		if uncached {
			// A stale byte cookie can be EOF in the new view; it is not a
			// complete enumeration. No bytes from the old view may be cached.
			if len(data) != 0 || server.getHandle(id).readData != nil {
				t.Fatal("cached old namespace view")
			}
		} else if !bytes.Equal(data, old[len(first):]) {
			t.Fatal("ordinary cached stream changed")
		}
		data, err = read(2, 0, 4096)
		if err != nil || !bytes.Equal(data, fresh) {
			t.Fatalf("rewind must return complete fresh view: %v %x", err, data)
		}
		data, err = read(3, 0, 4096)
		if err != fuse.EIO || data != nil {
			t.Fatalf("operational error became successful data: %v %x", err, data)
		}
		if uncached && h.calls != 5 {
			t.Fatalf("not refreshed per actual request: %d", h.calls)
		}
	}
}
