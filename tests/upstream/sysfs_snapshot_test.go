package mount

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestSysfsRegistrationSnapshot(t *testing.T) {
	service := &MountService{}
	service.NewMountHelper()
	parser, err := newMountInfoParser(nil, nil, false, true, false, service)
	if err != nil {
		t.Fatal(err)
	}
	// Kernel metadata only: no process, container, FUSE request or nsenter service.
	data := []byte("10 1 0:1 / /sys ro,nosuid,nodev,noexec - sysfs sysfs rw\n" +
		"11 10 0:2 /sys/devices/virtual /sys/devices/virtual rw,nosuid,nodev - fuse sysboxfs rw\n" +
		"12 11 0:3 /null /sys/devices/virtual/net/lo/ifindex ro - devtmpfs devtmpfs rw\n" +
		"14 11 0:2 /sys/devices/virtual/net/lo/statistics /sys/devices/virtual/net/lo/statistics ro - fuse sysboxfs rw\n" +
		"13 10 0:4 / /sys/custom\\040path ro - tmpfs tmpfs ro\n")
	if err = parser.parseData(data); err != nil {
		t.Fatal(err)
	}
	p := parser.SysfsPolicy()
	if len(p) != 5 {
		t.Fatal(p)
	}
	for _, entry := range p {
		switch entry.Path {
		case "/sys":
			if entry.Root != "/" || entry.FsType != "sysfs" {
				t.Fatal("lost genuine root metadata", entry)
			}
			if entry.Flags&(unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC) != unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC {
				t.Fatal(entry)
			}
		case "/sys/devices/virtual":
			if !entry.Emulated {
				t.Fatal("FUSE backing recursion", entry)
			}
		case "/sys/devices/virtual/net/lo/ifindex":
			if entry.Emulated || entry.MountID != 12 {
				t.Fatal("lost nested mask", entry)
			}
		case "/sys/devices/virtual/net/lo/statistics":
			if !entry.ReadonlyNetAlias || entry.Emulated {
				t.Fatal("readonly passthrough alias not recognized", entry)
			}
		case "/sys/custom path":
		default:
			t.Fatal("undecoded metadata", entry)
		}
	}
}

func TestSysfsRegistrationRootMetadata(t *testing.T) {
	for _, fixture := range []struct{ fs, encoded, decoded string }{
		{"sysfs", "/", "/"},
		{"tmpfs", "/", "/"},
		{"devtmpfs", "/null", "/null"},
		{"sysfs", "/devices", "/devices"},
		{"sysfs", `/devices/custom\040path`, "/devices/custom path"},
	} {
		service := &MountService{}
		service.NewMountHelper()
		parser, err := newMountInfoParser(nil, nil, false, true, false, service)
		if err != nil {
			t.Fatal(err)
		}
		if err = parser.parseData([]byte("10 1 0:1 " + fixture.encoded + " /sys ro - " + fixture.fs + " source rw\n")); err != nil {
			t.Fatal(err)
		}
		policy := parser.SysfsPolicy()
		if len(policy) != 1 || policy[0].Root != fixture.decoded || policy[0].FsType != fixture.fs || policy[0].MountID != 10 {
			t.Fatalf("root metadata lost: %+v", policy)
		}
	}
}
