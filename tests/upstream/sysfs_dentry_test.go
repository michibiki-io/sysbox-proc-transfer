package fuse

import (
	bfuse "bazil.org/fuse"
	bfusefs "bazil.org/fuse/fs"
	"context"
	"github.com/nestybox/sysbox-fs/domain"
	"os"
	"strings"
	"syscall"
	"testing"
)

type dentryContainer struct {
	domain.ContainerIface
	ready bool
}

func (c dentryContainer) SysfsSourceAncestor(path string) (bool, bool, uint32, uint32) {
	source := "/sys/devices/virtual/net/lo/ifalias"
	return c.ready, path == source || strings.HasPrefix(source, path+"/"), 10000, 10000
}

type dentryNode struct {
	domain.IOnodeIface
	name, path string
}

func (n dentryNode) Name() string { return n.name }
func (n dentryNode) Path() string { return n.path }

type dentryIO struct{ domain.IOServiceIface }

func (dentryIO) NewIOnode(name, path string, mode os.FileMode) domain.IOnodeIface {
	return dentryNode{name: name, path: path}
}

type dentryHandler struct {
	domain.HandlerIface
	err error
}

func (h dentryHandler) Lookup(domain.IOnodeIface, *domain.HandlerRequest) (os.FileInfo, error) {
	return nil, h.err
}

type dentryHandlers struct {
	domain.HandlerServiceIface
	err error
}

func (h dentryHandlers) LookupHandler(domain.IOnodeIface) (domain.HandlerIface, bool) {
	return dentryHandler{err: h.err}, true
}

// Exercise the actual Lookup error path. A mounted positive identity must not
// become an invalid FUSE entry merely because a different caller is rejected.
func TestProtectedNetworkLookupFailure(t *testing.T) {
	t.Setenv("SYSBOX_SYSFS_TRANSFER_HELPER", "/trusted/helper")
	for _, kind := range []os.FileMode{os.ModeDir, 0, os.ModeSymlink} {
		for _, failure := range []syscall.Errno{syscall.ENOENT, syscall.EPERM, syscall.EIO, syscall.ESRCH} {
			path := "/sys/devices/virtual/net/lo"
			cntr := dentryContainer{ready: true}
			server := &fuseServer{container: cntr, serveContainer: cntr, service: &FuseServerService{ios: dentryIO{}, hds: dentryHandlers{err: failure}}}
			req := &domain.HandlerRequest{Name: "lo", Path: path, Container: cntr}
			old := &bfuse.Attr{Inode: 77, Mode: kind | 0755, Size: 123, Uid: 12345, Gid: 23456, Valid: 123}
			identity := server.networkLookupNode(req, old, domain.FileInfo{Fmode: kind | 0755, FisDir: kind&os.ModeDir != 0})
			parent := NewDir(&domain.HandlerRequest{Name: "net", Path: "/sys/devices/virtual/net"}, &bfuse.Attr{Mode: os.ModeDir | 0555}, server)
			var resp bfuse.LookupResponse
			node, err := parent.Lookup(context.Background(), &bfuse.LookupRequest{Name: "lo"}, &resp)
			if err != nil || resp.EntryValid != 0 {
				t.Fatalf("protection invalidated: %v %+v", err, resp)
			}
			provider := node.(interface{ LookupIdentityNode() bfusefs.Node })
			if provider.LookupIdentityNode() != identity {
				t.Fatal("protocol identity changed")
			}
			var attr bfuse.Attr
			if err := node.Attr(context.Background(), &attr); err != nil {
				t.Fatal(err)
			}
			if attr.Inode != 77 || attr.Mode.Type() != kind || attr.Valid != 0 || attr.Size != 0 || attr.Uid != 0 || attr.Gid != 0 || attr.Mode.Perm()&0222 != 0 {
				t.Fatalf("cached view or writable metadata exposed: %+v", attr)
			}
			// Non-policy names, missing identities and bootstrap failures retain
			// the original operational error rather than a false positive entry.
			for _, change := range []string{"unprotected", "unknown-identity", "bootstrap"} {
				name := "lo"
				if change == "unprotected" {
					name = "absent"
				}
				if change == "unknown-identity" {
					delete(server.networkIdentities, path)
				}
				if change == "bootstrap" {
					server.serveContainer = dentryContainer{}
				}
				_, err := parent.Lookup(context.Background(), &bfuse.LookupRequest{Name: name}, new(bfuse.LookupResponse))
				if err != bfuse.Errno(failure) {
					t.Fatalf("%s error changed: %v", change, err)
				}
			}
		}
	}
}
