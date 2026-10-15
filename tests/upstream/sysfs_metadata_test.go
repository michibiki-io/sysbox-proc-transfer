package implementations

import (
	"bufio"
	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
	"os/exec"
	"strconv"
	"strings"
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

// A live grandchild cannot use the host metadata exception, even though its
// parent is a daemon-owned direct child. All processes here belong to this test.
func TestNetworkMetadataGrandchild(t *testing.T) {
	t.Setenv("SYSBOX_SYSFS_TRANSFER_HELPER", "/trusted/helper")
	cmd := exec.Command("/bin/sh", "-c", "sleep 20 & p=$!; echo $p; wait $p")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 1 {
		t.Fatalf("grandchild PID: %q %v", line, err)
	}
	defer unix.Kill(pid, unix.SIGKILL)
	req := &domain.HandlerRequest{Pid: uint32(pid), Container: sourceContainer{ready: true, ancestor: true}}
	if _, handled, err := networkSourceLookup("/sys/devices/virtual/net/lo", req); !handled || err != syscall.EPERM {
		t.Fatalf("grandchild metadata admitted: %v %v", handled, err)
	}
}
