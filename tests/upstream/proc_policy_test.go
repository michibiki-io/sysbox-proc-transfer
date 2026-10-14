// SPDX-License-Identifier: MIT
package seccomp

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

type procPolicyParser struct {
	domain.MountInfoParserIface
	info *domain.MountInfo
}

func (p procPolicyParser) GetInfo(string) *domain.MountInfo { return p.info }

type procPolicyProcess struct {
	domain.ProcessIface
	inode uint64
}

func (p procPolicyProcess) UserNsInode() (domain.Inode, error) { return p.inode, nil }

type procPolicyContainer struct{ domain.ContainerIface }

func (procPolicyContainer) InitProc() domain.ProcessIface { return procPolicyProcess{inode: 1} }
func (procPolicyContainer) ProcRoPaths() []string         { return nil }
func (procPolicyContainer) ProcMaskPaths() []string       { return nil }

type procPolicyMountHelper struct{ domain.MountHelperIface }

func (procPolicyMountHelper) ProcMounts() []string { return nil }

type procPolicyMountService struct{ domain.MountServiceIface }

func (procPolicyMountService) MountHelper() domain.MountHelperIface { return procPolicyMountHelper{} }

func TestProcPolicyBeforeNestedTransfer(t *testing.T) {
	t.Setenv("SYSBOX_PROC_TRANSFER_HELPER", "must-not-execute")
	cases := []struct {
		name     string
		info     *domain.MountInfo
		flags    uint64
		readonly bool
	}{
		{"inherited-readonly", &domain.MountInfo{VfsOptions: map[string]string{"ro": ""}}, unix.MS_NOSUID, true},
		{"readwrite", &domain.MountInfo{VfsOptions: map[string]string{"rw": ""}}, unix.MS_NOSUID, false},
		{"explicit-readonly", &domain.MountInfo{VfsOptions: map[string]string{"rw": ""}}, unix.MS_RDONLY | unix.MS_NOSUID, true},
		{"missing-proc-info", nil, unix.MS_NOSUID, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			request := &mountSyscallInfo{
				syscallCtx:          syscallCtx{root: "/non-root", cntr: procPolicyContainer{}, processInfo: procPolicyProcess{inode: 2}, tracer: &syscallTracer{service: &SyscallMonitorService{mts: procPolicyMountService{}}}},
				MountSyscallPayload: &domain.MountSyscallPayload{Mount: domain.Mount{Flags: c.flags}},
			}
			// Deliberately unsupported root causes the real nested dispatcher to return
			// before any helper execution. Its flags must already carry the outer policy.
			response, err := request.processProcMount(procPolicyParser{info: c.info})
			if err != nil || response == nil || response.Error != int32(syscall.ENOTSUP) {
				t.Fatalf("expected nested-path rejection, got %+v, %v", response, err)
			}
			if got := request.Flags&unix.MS_RDONLY != 0; got != c.readonly {
				t.Fatalf("readonly before nested dispatch=%v, want %v", got, c.readonly)
			}
			if request.Flags&unix.MS_NOSUID == 0 {
				t.Fatal("original mount flags lost")
			}
		})
	}
}

func TestProcRequesterThreadPidfd(t *testing.T) {
	for _, result := range []error{nil, syscall.EINVAL, syscall.ENOSYS, syscall.ESRCH, syscall.EPERM} {
		calls := 0
		fd, err := openProcRequesterPidfd(12345, func(tid, flags int) (int, error) {
			calls++
			if tid != 12345 || flags != 0x80 {
				t.Fatalf("wrong requester: tid=%d flags=%#x", tid, flags)
			}
			if result != nil {
				return -1, result
			}
			return 42, nil
		})
		if calls != 1 || err != result || (err == nil && fd != 42) {
			t.Fatalf("fallback or lost errno: fd=%d err=%v calls=%d", fd, err, calls)
		}
	}
}

func TestProcTransferInvalidNotificationDoesNotLaunch(t *testing.T) {
	launched := false
	output, err := runProcTransfer(-1, 1, func() ([]byte, error) { launched = true; return []byte("launched"), nil })
	if err == nil || launched || output != nil {
		t.Fatalf("invalid listener launched helper: %v %v %q", err, launched, output)
	}
}

//go:embed testdata/proc_lifecycle.c
var procLifecycleFixture []byte

func TestProcTransferRealNotification(t *testing.T) {
	work := t.TempDir()
	source := filepath.Join(work, "lifecycle.c")
	binary := filepath.Join(work, "lifecycle")
	if err := os.WriteFile(source, procLifecycleFixture, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cc", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v %s", err, output)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(pair[0]), "parent")
	child := os.NewFile(uintptr(pair[1]), "child")
	defer parent.Close()
	defer child.Close()
	cmd := exec.Command(binary, "provide")
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stderr = os.Stderr
	if err := unix.SetsockoptTimeval(pair[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	// Release the parent's peer so fixture startup failure produces EOF.
	child.Close()
	data, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, size, _, _, err := unix.Recvmsg(pair[0], data, control, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := unix.ParseSocketControlMessage(control[:size])
	if err != nil || len(messages) != 1 {
		t.Fatalf("rights message: %v %v", messages, err)
	}
	rights, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(rights) != 1 {
		t.Fatalf("listener rights: %v %v", rights, err)
	}
	fd := rights[0]
	defer unix.Close(fd)
	request, err := libseccomp.NotifReceive(libseccomp.ScmpFd(fd))
	if err != nil {
		t.Fatal(err)
	}
	// Pin actual requester descriptors before the production launch boundary.
	pfd, err := openProcRequesterPidfd(int(request.Pid), unix.PidfdOpen)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pfd)
	for _, path := range []string{"ns/user", "ns/mnt", "ns/pid", "root"} {
		f, err := os.Open(filepath.Join("/proc", fmt.Sprint(request.Pid), path))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
	}
	calls := 0
	launch := func() ([]byte, error) { calls++; return []byte("ran"), nil }
	if _, err := runProcTransfer(int32(fd), request.ID, launch); err != nil || calls != 1 {
		t.Fatalf("valid notification: %v calls=%d", err, calls)
	}
	if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.Read(data); err != nil || data[0] != 'I' {
		t.Fatalf("interruption checkpoint: %v %q", err, data)
	}
	poll := []unix.PollFd{{Fd: int32(pfd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
		t.Fatalf("requester should remain alive: %d %v", n, err)
	}
	if _, err := runProcTransfer(int32(fd), request.ID, launch); err == nil || calls != 1 {
		t.Fatalf("invalid original ID launched: %v calls=%d", err, calls)
	}
	if err := libseccomp.NotifRespond(libseccomp.ScmpFd(fd), &libseccomp.ScmpNotifResp{ID: request.ID}); err == nil {
		t.Fatal("success delivered to invalid original notification")
	}
	if _, err := parent.Write([]byte("T")); err != nil {
		t.Fatal(err)
	}
}
