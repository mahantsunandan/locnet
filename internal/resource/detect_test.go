package resource

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

// TestForwarderWithNoBackendIsNotAService is the bug that told a whole network
// a machine had a VNC server when it had none.
//
// LocNet's own port share listens on the overlay address, so a scan that dials
// the overlay finds it and reports the service — whether or not anything is
// behind the forwarder. The peer then connects, gets a socket that closes
// without a byte, and blames the VNC server it can see advertised.
func TestForwarderWithNoBackendIsNotAService(t *testing.T) {
	// Stand in for locnetd's forwarder: accepts, has nothing behind it.
	fwd, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fwd.Close()
	go func() {
		for {
			c, err := fwd.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	fwdPort := uint16(fwd.Addr().(*net.TCPAddr).Port)

	// A backend address with nothing on it.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	// Pretend the forwarder occupies a catalog port.
	old := Catalog
	Catalog = []KnownService{{Name: "vnc-1", Port: fwdPort, Client: "vnc"}}
	defer func() { Catalog = old }()

	addr := netip.MustParseAddr("127.0.0.1")

	if got := DetectServices(context.Background(), addr, nil); len(got) != 1 {
		t.Fatalf("without the share map the forwarder should look like a service, got %+v", got)
	}
	got := DetectServices(context.Background(), addr, map[uint16]string{fwdPort: deadAddr})
	if len(got) != 0 {
		t.Errorf("advertised %+v — a forwarder with a dead backend is not a service", got)
	}
}

// And the other half: a forwarder with a live backend is a real service and
// must still be advertised.
func TestForwarderWithALiveBackendIsAService(t *testing.T) {
	fwd, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fwd.Close()
	fwdPort := uint16(fwd.Addr().(*net.TCPAddr).Port)

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	old := Catalog
	Catalog = []KnownService{{Name: "vnc-1", Port: fwdPort, Client: "vnc"}}
	defer func() { Catalog = old }()

	got := DetectServices(context.Background(), netip.MustParseAddr("127.0.0.1"),
		map[uint16]string{fwdPort: backend.Addr().String()})
	if len(got) != 1 || got[0].Name != "vnc-1" {
		t.Errorf("got %+v, want the service the forwarder really fronts", got)
	}
}
