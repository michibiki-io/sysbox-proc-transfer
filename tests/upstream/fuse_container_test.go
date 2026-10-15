package fuse

import (
	bfuse "bazil.org/fuse"
	bfusefs "bazil.org/fuse/fs"
	"context"
	"github.com/nestybox/sysbox-fs/domain"
	"os"
	"syscall"
	"testing"
)

type ownerContainer struct {
	domain.ContainerIface
	dead bool
	pid  uint32
}

func (c *ownerContainer) InitPid() uint32 {
	if c.dead {
		return 0
	}
	return c.pid
}
func (c *ownerContainer) UID() uint32 { return 10000 }
func (c *ownerContainer) GID() uint32 { return 10000 }
func (c *ownerContainer) SysfsSourceAncestor(string) (bool, bool, uint32, uint32) {
	return !c.dead, true, 10000, 10000
}

type ownerNode struct{ domain.IOnodeIface }

func (ownerNode) SetOpenFlags(int)        {}
func (ownerNode) SetOpenMode(os.FileMode) {}

type ownerIO struct{ domain.IOServiceIface }

func (ownerIO) NewIOnode(string, string, os.FileMode) domain.IOnodeIface { return ownerNode{} }

type ownerProcess struct{ domain.ProcessIface }

func (ownerProcess) UsernsRootUidGid() (uint32, uint32, error) { return 10000, 10000, nil }

type ownerProcesses struct{ domain.ProcessServiceIface }

func (ownerProcesses) ProcessCreate(uint32, uint32, uint32) domain.ProcessIface {
	return ownerProcess{}
}

type ownerHandler struct {
	domain.HandlerIface
	t     *testing.T
	want  domain.ContainerIface
	calls int
}

func (h *ownerHandler) check(r *domain.HandlerRequest) {
	h.t.Helper()
	h.calls++
	if r.Container != h.want {
		h.t.Fatalf("wrong container: %p want %p", r.Container, h.want)
	}
	if r.Pid != 42 || r.Uid != 10001 || r.Gid != 10002 {
		h.t.Fatalf("caller changed: %+v", r)
	}
}
func (h *ownerHandler) Lookup(_ domain.IOnodeIface, r *domain.HandlerRequest) (os.FileInfo, error) {
	h.check(r)
	r.SkipIdRemap = true
	return domain.FileInfo{Fmode: 0444, Fsys: (*syscall.Stat_t)(nil)}, nil
}
func (h *ownerHandler) Open(_ domain.IOnodeIface, r *domain.HandlerRequest) (bool, error) {
	h.check(r)
	return false, nil
}
func (h *ownerHandler) Read(_ domain.IOnodeIface, r *domain.HandlerRequest) (int, error) {
	h.check(r)
	return 0, nil
}
func (h *ownerHandler) Write(_ domain.IOnodeIface, r *domain.HandlerRequest) (int, error) {
	h.check(r)
	return 0, nil
}
func (h *ownerHandler) ReadLink(_ domain.IOnodeIface, r *domain.HandlerRequest) (string, error) {
	h.check(r)
	return "lo", nil
}
func (h *ownerHandler) ReadDirAll(_ domain.IOnodeIface, r *domain.HandlerRequest) ([]os.FileInfo, error) {
	h.check(r)
	return nil, nil
}

type ownerHandlers struct {
	domain.HandlerServiceIface
	handler *ownerHandler
}

func (h ownerHandlers) LookupHandler(domain.IOnodeIface) (domain.HandlerIface, bool) {
	return h.handler, true
}
func (h ownerHandlers) ProcessService() domain.ProcessServiceIface { return ownerProcesses{} }

// Exercise actual request construction at every handler dispatch, including
// crossing into net from its parent. Shared state may outlive its first init.
func TestNetworkOwningContainer(t *testing.T) {
	first := &ownerContainer{pid: 11}
	own := &ownerContainer{pid: 22}
	for _, enabled := range []bool{false, true} {
		value := ""
		if enabled {
			value = "/trusted/helper"
		}
		t.Setenv("SYSBOX_SYSFS_TRANSFER_HELPER", value)
		for _, dead := range []bool{false, true} {
			first.dead = dead
			for _, path := range []string{"/proc/test", "/sys/devices/virtual/net/lo"} {
				want := domain.ContainerIface(first)
				if enabled && path != "/proc/test" {
					want = own
				}
				handler := &ownerHandler{t: t, want: want}
				server := newFuseServer("/", "/unused", first, own, &FuseServerService{ios: ownerIO{}, hds: ownerHandlers{handler: handler}})
				server.nodeDB = make(map[string]*bfusefs.Node)
				attr := &bfuse.Attr{Inode: 77, Mode: 0444}
				file := NewFile(&domain.HandlerRequest{Name: "lo", Path: path, SkipIdRemap: true}, attr, server)
				dir := NewDir(&domain.HandlerRequest{Path: path}, attr, server)
				head := bfuse.Header{Pid: 42, Uid: 10001, Gid: 10002}
				ctx := context.Background()
				if _, err := file.Open(ctx, &bfuse.OpenRequest{Header: head}, new(bfuse.OpenResponse)); err != nil {
					t.Fatal(err)
				}
				if err := file.Read(ctx, &bfuse.ReadRequest{Header: head}, new(bfuse.ReadResponse)); err != nil {
					t.Fatal(err)
				}
				if err := file.Write(ctx, &bfuse.WriteRequest{Header: head}, new(bfuse.WriteResponse)); err != nil {
					t.Fatal(err)
				}
				if _, err := file.Readlink(ctx, &bfuse.ReadlinkRequest{Header: head}); err != nil {
					t.Fatal(err)
				}
				if _, err := dir.ReadDirAll(ctx, &bfuse.ReadRequest{Header: head}); err != nil {
					t.Fatal(err)
				}
				if err := file.Getattr(ctx, &bfuse.GetattrRequest{Header: head}, new(bfuse.GetattrResponse)); err != nil {
					t.Fatal(err)
				}
				parentPath, name := "/proc", "test"
				if path != "/proc/test" {
					parentPath, name = "/sys/devices/virtual", "net"
				}
				parent := NewDir(&domain.HandlerRequest{Path: parentPath}, attr, server)
				if _, err := parent.Lookup(ctx, &bfuse.LookupRequest{Header: head, Name: name}, new(bfuse.LookupResponse)); err != nil {
					t.Fatal(err)
				}
				// Create shares Open/Lookup request construction and must select by child path.
				if _, _, err := parent.Create(ctx, &bfuse.CreateRequest{Header: head, Name: name}, new(bfuse.CreateResponse)); err != nil {
					t.Fatal(err)
				}
				expected := 8
				if enabled && path != "/proc/test" {
					expected = 9
				}
				if handler.calls != expected {
					t.Fatalf("dispatch coverage %d want %d", handler.calls, expected)
				}
				if server.container != first || server.serveContainer != own {
					t.Fatal("state/owner reference changed")
				}
				if enabled && path != "/proc/test" {
					req := &domain.HandlerRequest{Path: path, Container: own}
					identity := server.networkLookupNode(req, attr, domain.FileInfo{})
					node, ok := server.networkProtectionLookup(req)
					if !ok || node.(interface{ LookupIdentityNode() bfusefs.Node }).LookupIdentityNode() != identity {
						t.Fatal("own protection snapshot lost")
					}
					if server.requestContainer(path).InitPid() != 22 {
						t.Fatal("exited first init affected owner")
					}
				}
			}
		}
	}
	// Existing pinned-source constructor callers still get their own container.
	legacy := NewFuseServer("/", "/unused", own, nil).(*fuseServer)
	if legacy.container != own || legacy.serveContainer != own {
		t.Fatal("constructor lost owner")
	}
}
