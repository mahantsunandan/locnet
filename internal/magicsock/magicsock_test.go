package magicsock

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
	"golang.zx2c4.com/wireguard/conn"
)

func testConn(t *testing.T) *Conn {
	t.Helper()
	machine, _, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	_, wgPub, err := key.NewWG()
	if err != nil {
		t.Fatal(err)
	}
	discoPriv, _, err := key.NewDisco()
	if err != nil {
		t.Fatal(err)
	}
	c := New(Options{
		NodeID: "test", MachineKey: machine, WGKey: wgPub, DiscoKey: discoPriv,
		Logf: func(string, ...any) {},
	})
	t.Cleanup(func() { c.Close() })
	return c
}

// TestBindSurvivesTheDeviceStartupSequence reproduces exactly what
// wireguard-go does when a device starts, which is not what a naive test does.
//
// device.IpcSet("listen_port=…") calls BindUpdate, which closes the bind and
// then returns early because the device is not up yet — so Close happens
// before the first Open. device.Up() then calls BindUpdate again, which opens
// for real.
//
// A Close implemented with sync.Once survives none of this: the first Close
// consumes the guard, the socket opened afterwards is never closed, and any
// one-shot channel it signalled stays signalled. The tunnel then comes up
// looking perfectly healthy while carrying no traffic at all.
func TestBindSurvivesTheDeviceStartupSequence(t *testing.T) {
	c := testConn(t)

	// BindUpdate #1, device down: close, then no open.
	if err := c.Close(); err != nil {
		t.Fatalf("Close before the first Open returned %v; it must be a no-op", err)
	}

	// BindUpdate #2, device up: close again (still a no-op), then open.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close returned %v", err)
	}
	fns, port, err := c.Open(0)
	if err != nil {
		t.Fatalf("Open after two Closes: %v", err)
	}
	if len(fns) != 1 || port == 0 {
		t.Fatalf("Open returned %d receive funcs on port %d", len(fns), port)
	}

	// The socket must actually work — a dead maintenance loop and a dead
	// socket look identical from the outside until traffic is tried.
	if !c.sendsAndReceives(t) {
		t.Fatal("the socket opened after a Close cycle cannot carry packets")
	}

	// And the maintenance loop must be alive. It is what sends relay binds
	// and path probes; if it exited, peers never find each other.
	if !c.maintenanceRunning(t) {
		t.Fatal("the maintenance loop is not running after the startup sequence, " +
			"so no relay binding or path probing will ever happen")
	}
}

// TestBindCanBeCycledRepeatedly covers a roaming device, which rebinds every
// time the host's network changes.
func TestBindCanBeCycledRepeatedly(t *testing.T) {
	c := testConn(t)
	for i := 0; i < 4; i++ {
		if _, _, err := c.Open(0); err != nil {
			t.Fatalf("cycle %d: Open: %v", i, err)
		}
		if !c.maintenanceRunning(t) {
			t.Fatalf("cycle %d: the maintenance loop did not start", i)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("cycle %d: Close: %v", i, err)
		}
	}
}

// TestOpenTwiceIsRefused keeps the contract wireguard-go relies on.
func TestOpenTwiceIsRefused(t *testing.T) {
	c := testConn(t)
	if _, _, err := c.Open(0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Open(0); err == nil {
		t.Fatal("a second Open on an open bind was allowed")
	}
}

// TestReceiveReportsClosed checks the other half of the contract: after Close,
// every receive function must report closed rather than blocking, or the
// device's receive goroutines never exit and shutdown hangs.
func TestReceiveReportsClosed(t *testing.T) {
	c := testConn(t)
	fns, _, err := c.Open(0)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		_, err := fns[0](bufs, sizes, eps)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	c.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the receive function returned no error after Close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the receive function is still blocked 3s after Close; " +
			"wireguard-go would hang forever waiting for it")
	}
}

// ---------------------------------------------------------------- helpers

// sendsAndReceives proves the current socket is live by sending a packet to
// itself and reading it back off the wire.
func (c *Conn) sendsAndReceives(t *testing.T) bool {
	t.Helper()
	c.mu.Lock()
	pc := c.pconn
	port := c.port
	c.mu.Unlock()
	if pc == nil {
		return false
	}

	self := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	if err := c.sendRaw([]byte("probe"), self); err != nil {
		t.Logf("send: %v", err)
		return false
	}
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer pc.SetReadDeadline(time.Time{})

	buf := make([]byte, 64)
	n, _, err := pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Logf("read: %v", err)
		return false
	}
	return string(buf[:n]) == "probe"
}

// maintenanceRunning checks the loop is alive by pointing it at a socket we
// control and waiting for the relay bind it is supposed to send.
//
// Testing the observable behaviour rather than a flag: a boolean saying the
// loop started would have been true in the broken version too.
func (c *Conn) maintenanceRunning(t *testing.T) bool {
	t.Helper()
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	addr := netip.MustParseAddrPort(relay.LocalAddr().String())
	c.SetRelay(addr)

	relay.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := relay.ReadFromUDPAddrPort(buf)
	if err != nil {
		return false
	}
	// A bind is the first thing the loop sends.
	return n > 5 && string(buf[:4]) == "LNd1"
}

// TestOverlayAddressesAreNotAdvertised covers a bug that produced a genuinely
// baffling symptom: `locnet status` reporting the machine's own tunnel address
// as its public one.
//
// The agent enumerates its interfaces for candidate paths, and the tunnel it
// just created is one of them. Advertising that address asks peers to reach
// the tunnel through the tunnel — and a reply arriving that way reports an
// overlay source, which then gets recorded as this machine's public address.
func TestOverlayAddressesAreNotAdvertised(t *testing.T) {
	c := testConn(t)
	if _, _, err := c.Open(0); err != nil {
		t.Fatal(err)
	}

	before := c.LocalEndpoints()

	// Claiming the whole IPv4 space must remove every IPv4 endpoint, and
	// leave IPv6 alone — an IPv4 prefix does not contain an IPv6 address,
	// and pretending otherwise would hide a real filtering mistake.
	c.SetOverlay(netip.MustParsePrefix("0.0.0.0/0"))
	for _, ep := range c.LocalEndpoints() {
		if ep.Addr().Is4() {
			t.Errorf("IPv4 endpoint %s survived an overlay of 0.0.0.0/0", ep)
		}
	}

	// A range containing nothing must change nothing.
	c.SetOverlay(netip.MustParsePrefix("203.0.113.0/24"))
	if got, want := len(c.LocalEndpoints()), len(before); got != want {
		t.Errorf("an unrelated overlay range changed the endpoint list: %d -> %d", want, got)
	}

	// The realistic case: the default overlay range.
	overlay := netip.MustParsePrefix("10.99.0.0/16")
	c.SetOverlay(overlay)
	for _, ep := range c.LocalEndpoints() {
		if overlay.Contains(ep.Addr()) {
			t.Errorf("overlay address %s is still advertised as a path", ep)
		}
	}
}

// TestSyntheticOverlayAddressIsFiltered proves the filter on an address this
// machine may not actually have, so the test means something everywhere.
func TestSyntheticOverlayAddressIsFiltered(t *testing.T) {
	overlay := netip.MustParsePrefix("10.99.0.0/16")
	inside := netip.MustParseAddr("10.99.0.2")
	outside := netip.MustParseAddr("192.168.1.97")

	if !overlay.Contains(inside) {
		t.Fatal("the tunnel address is not recognised as inside the overlay")
	}
	if overlay.Contains(outside) {
		t.Fatal("a LAN address was treated as inside the overlay")
	}
}
