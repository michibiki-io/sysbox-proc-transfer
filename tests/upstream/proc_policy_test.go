// SPDX-License-Identifier: MIT
package seccomp

import (
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
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
