package sysfstransfer

import (
	"errors"
	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestCompletePolicy(t *testing.T) {
	p := []domain.SysfsProtection{
		{Path: "/sys/devices/virtual/net/lo/ifindex", MountID: 6, FsType: "tmpfs", Flags: unix.MS_RDONLY},
		{Path: "/sys", FsType: "sysfs", Root: "/", MountID: 1, Flags: unix.MS_RDONLY | unix.MS_NOEXEC},
		{Path: "/sys/firmware", MountID: 2, FsType: "tmpfs"},
		{Path: "/sys/devices/virtual", MountID: 3, FsType: "fuse", Emulated: true},
		{Path: "/sys/devices/virtual/net/lo/statistics", MountID: 4, FsType: "sysfs", Flags: unix.MS_RDONLY},
		{Path: "/sys/devices/virtual/net/lo/statistics/rx_bytes", MountID: 5, FsType: "tmpfs"},
	}
	mounts, floor, err := Plan(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 5 || floor != unix.MS_RDONLY|unix.MS_NOEXEC {
		t.Fatalf("lost policy: %+v floor=%x", mounts, floor)
	}
	if mounts[0].Path != "/sys/devices/virtual" || mounts[2].Path != "/sys/devices/virtual/net/lo/statistics" {
		t.Fatal("parent order", mounts)
	}
	backing, _, err := Plan(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(backing) != 4 {
		t.Fatal("backing dropped OCI masks/RO", backing)
	}
	for _, m := range backing {
		if m.Emulated {
			t.Fatal("recursive FUSE backing")
		}
	}
	// No mutation of registration metadata by sorting/planning.
	if p[0].MountID != 6 {
		t.Fatal("mutated policy")
	}
}
func TestMalformedPolicy(t *testing.T) {
	for _, p := range [][]domain.SysfsProtection{
		nil, {{Path: "/sys", FsType: "sysfs", Root: "/", MountID: 0}},
		{{Path: "/sys", FsType: "sysfs", Root: "/", MountID: 1}, {Path: "/sys/../etc", MountID: 2}},
		{{Path: "/sys", FsType: "sysfs", Root: "/", MountID: 1}, {Path: "/proc/sys", MountID: 2}},
		{{Path: "/sys", FsType: "sysfs", Root: "/", MountID: 1}, {Path: "/sys", FsType: "sysfs", Root: "/", MountID: 2}},
	} {
		if _, _, err := Plan(p, false); err == nil {
			t.Fatalf("accepted malformed policy %+v", p)
		}
	}
}
func TestFlagsAndErrno(t *testing.T) {
	for _, flags := range []uint64{unix.MS_BIND, unix.MS_MOVE, unix.MS_REMOUNT, unix.MS_REC, unix.MS_RELATIME | unix.MS_STRICTATIME, 1 << 63} {
		if !errors.Is(Validate(flags, ""), syscall.EINVAL) {
			t.Fatalf("flags %x", flags)
		}
	}
	if Validate(unix.MS_RDONLY|unix.MS_NOSUID, "") != nil {
		t.Fatal("supported flags")
	}
	if Validate(0, "rw") != syscall.EINVAL {
		t.Fatal("data accepted")
	}
	if Errno(errors.Join(errors.New("pin source"), syscall.EACCES)) != syscall.EACCES {
		t.Fatal("acquisition errno lost")
	}
}

// The task anchor must remain usable for a live task and must not switch to
// another task after exit. This supplements the actual nonleader runtime case.
func TestTaskAnchorExit(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "20")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	dir, thread, err := pinTask(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	defer unix.Close(thread)
	if !OwnMetadataTask(uint32(cmd.Process.Pid)) {
		t.Fatal("own live worker not recognized")
	}
	fd, err := unix.Openat(dir, "ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child unexpectedly succeeded")
	}
	if OwnMetadataTask(uint32(cmd.Process.Pid)) {
		t.Fatal("dead worker accepted")
	}
	if !errors.Is(taskAlive(thread), syscall.ESRCH) {
		t.Fatal("dead task accepted")
	}
	fd, err = unix.Openat(dir, "ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
		t.Fatal("exited anchor returned namespace")
	}
}

// Embed the interface for irrelevant methods: these tests exercise only the
// production acquisition path, never launch a helper or perform a mount.
type acquisitionContainer struct {
	domain.ContainerIface
	policy []domain.SysfsProtection
}

func (c acquisitionContainer) IsRegistrationCompleted() bool         { return true }
func (c acquisitionContainer) UID() uint32                           { return uint32(os.Getuid()) }
func (c acquisitionContainer) GID() uint32                           { return uint32(os.Getgid()) }
func (c acquisitionContainer) UidSize() uint32                       { return 65536 }
func (c acquisitionContainer) GidSize() uint32                       { return 65536 }
func (c acquisitionContainer) InitPid() uint32                       { return uint32(os.Getpid()) }
func (c acquisitionContainer) SysfsPolicy() []domain.SysfsProtection { return c.policy }

func TestMissingAcquisition(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	mountID := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == "/sys" {
			mountID, _ = strconv.Atoi(fields[0])
			break
		}
	}
	if mountID == 0 {
		t.Fatal("test sysfs root absent")
	}
	c := acquisitionContainer{policy: []domain.SysfsProtection{{Path: "/sys", FsType: "sysfs", Root: "/", MountID: mountID}}}
	r, err := Acquire(c, uint32(unix.Gettid()), c.UID(), c.GID(), "/absent-issue5-target", 0, "", nil)
	if r != nil || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("target error changed: request=%v err=%v", r, err)
	}
	c.policy = append(c.policy, domain.SysfsProtection{Path: "/sys/absent-issue5-source", MountID: mountID})
	r, err = Acquire(c, uint32(unix.Gettid()), c.UID(), c.GID(), "/tmp", 0, "", nil)
	if r != nil || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("required source silently skipped: request=%v err=%v", r, err)
	}
}

func TestReadonlyNetworkAlias(t *testing.T) {
	p := []domain.SysfsProtection{{Path: "/sys", FsType: "sysfs", Root: "/", MountID: 1}, {Path: "/sys/devices/virtual", MountID: 2, FsType: "fuse", Emulated: true}, {Path: "/sys/devices/virtual/net/lo/statistics", MountID: 3, FsType: "fuse", Flags: unix.MS_RDONLY, ReadonlyNetAlias: true}}
	result, _, err := Plan(p, true)
	if err != nil || len(result) != 1 || !result[0].ReadonlyNetAlias {
		t.Fatal("alias policy lost", result, err)
	}
	p[2].ReadonlyNetAlias = false
	if _, _, err = Plan(p, true); err != syscall.ENOTSUP {
		t.Fatal("unsupported network FUSE must fail closed", err)
	}
	p[2].ReadonlyNetAlias = true
	p[2].Flags = 0
	if _, _, err = Plan(p, true); err != syscall.EINVAL {
		t.Fatal("unprotected alias accepted", err)
	}
}

// Both transfer and backing must reject unsupported roots before opening a
// target, acquiring namespaces, or returning any launchable Request.
func TestUnsupportedRoot(t *testing.T) {
	for _, root := range []domain.SysfsProtection{
		{Path: "/sys", MountID: 1, FsType: "tmpfs", Root: "/"},
		{Path: "/sys", MountID: 1, FsType: "devtmpfs", Root: "/null"},
		{Path: "/sys", MountID: 1, FsType: "fuse", Root: "/"},
		{Path: "/sys", MountID: 1, FsType: "sysfs", Root: "/devices"},
		{Path: "/sys", MountID: 1, FsType: "sysfs", Root: "/devices/custom path"},
		{Path: "/sys", MountID: 1, FsType: "sysfs"},
	} {
		for _, backing := range []bool{false, true} {
			mounts, floor, err := Plan([]domain.SysfsProtection{root}, backing)
			if err != syscall.ENOTSUP || mounts != nil || floor != 0 {
				t.Fatalf("unsupported root accepted: %+v backing=%v: %v", root, backing, err)
			}
			target := t.TempDir()
			sentinel := target + "/sentinel"
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			var channel *os.File
			if backing {
				channel = new(os.File) // Never touched: rejection precedes FD acquisition.
			}
			c := acquisitionContainer{policy: []domain.SysfsProtection{root}}
			r, err := Acquire(c, uint32(unix.Gettid()), c.UID(), c.GID(), target, 0, "", channel)
			if r != nil || err != syscall.ENOTSUP {
				t.Fatalf("launchable unsupported root: request=%v err=%v", r, err)
			}
			data, err := os.ReadFile(sentinel)
			entries, dirErr := os.ReadDir(target)
			if err != nil || string(data) != "unchanged" || dirErr != nil || len(entries) != 1 {
				t.Fatal("target changed", err, dirErr)
			}
		}
	}
}

func TestRootMountIDMismatch(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// A supported root still requires the exact registered source mount ID.
	c := acquisitionContainer{policy: []domain.SysfsProtection{{Path: "/sys", FsType: "sysfs", Root: "/", MountID: 2147483647}}}
	target := t.TempDir()
	r, err := Acquire(c, uint32(unix.Gettid()), c.UID(), c.GID(), target, 0, "", nil)
	if r != nil || !errors.Is(err, syscall.ESTALE) {
		t.Fatalf("root mount replacement accepted: request=%v err=%v", r, err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("target changed", err)
	}
}
