package implementations

import (
	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
	"syscall"
	"testing"
)

type sourceContainer struct {
	domain.ContainerIface
	ready, ancestor bool
}

func (c sourceContainer) SysfsSourceAncestor(string) (bool, bool, uint32, uint32) {
	return c.ready, c.ancestor, 10000, 10000
}
func TestNetworkSourceMetadata(t *testing.T) {
	t.Setenv("SYSBOX_SYSFS_TRANSFER_HELPER", "/trusted/helper")
	req := &domain.HandlerRequest{Pid: uint32(unix.Gettid()), Container: sourceContainer{ready: true, ancestor: true}}
	info, handled, err := networkSourceLookup("/sys/devices/virtual/net/lo", req)
	if !handled || err != nil || !info.IsDir() || info.Mode().Perm() != 0555 || !req.SkipIdRemap {
		t.Fatalf("metadata failed: %v %v %v", info, handled, err)
	}
	req.Container = sourceContainer{ready: true}
	if _, handled, err = networkSourceLookup("/sys/devices/virtual/net/lo", req); !handled || err != syscall.EPERM {
		t.Fatal("unregistered path admitted", handled, err)
	}
	req.Container = sourceContainer{ready: true, ancestor: true}
	req.Pid = ^uint32(0)
	if _, handled, err = networkSourceLookup("/sys/devices/virtual/net/lo", req); !handled || err != syscall.EPERM {
		t.Fatal("foreign/dead task admitted", handled, err)
	}
	req.Pid = uint32(unix.Gettid())
	req.Uid = 1001
	if _, handled, _ = networkSourceLookup("/sys/devices/virtual/net/lo", req); handled {
		t.Fatal("caller entered metadata exception")
	}
	req.Uid = 0
	req.Container = sourceContainer{}
	if _, handled, _ = networkSourceLookup("/sys/devices/virtual/net/lo", req); handled {
		t.Fatal("bootstrap changed")
	}
	if _, handled, _ = networkSourceLookup("/sys/kernel", req); handled {
		t.Fatal("scope escaped")
	}
	t.Setenv("SYSBOX_SYSFS_TRANSFER_HELPER", "")
	if _, handled, _ = networkSourceLookup("/sys/devices/virtual/net/lo", req); handled {
		t.Fatal("unset behavior changed")
	}
}
