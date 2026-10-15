package resource

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// KnownService is a port worth checking for.
type KnownService struct {
	Name string
	Port uint16
	// Client is the sort of program that connects to it, which is what
	// `locnet open` uses to choose a launcher.
	Client string
	Desc   string
}

// Catalog is the set of services LocNet knows how to find and connect to.
//
// It is deliberately short. A full port scan of every peer would be slow,
// noisy, and would mostly turn up things nobody wants to click on.
var Catalog = []KnownService{
	{Name: "ssh", Port: 22, Client: "ssh", Desc: "Secure shell"},
	{Name: "rdp", Port: 3389, Client: "rdp", Desc: "Windows Remote Desktop"},
	{Name: "vnc", Port: 5900, Client: "vnc", Desc: "Screen sharing"},
	// One entry per display LocNet might choose. It picks the first display
	// nothing has claimed, and on a machine with somebody logged in that is
	// rarely :1 — so a catalog that stopped at :1 could not find the server
	// LocNet had just started.
	{Name: "vnc-1", Port: 5901, Client: "vnc", Desc: "Screen sharing (display 1)"},
	{Name: "vnc-2", Port: 5902, Client: "vnc", Desc: "Screen sharing (display 2)"},
	{Name: "vnc-3", Port: 5903, Client: "vnc", Desc: "Screen sharing (display 3)"},
	{Name: "vnc-4", Port: 5904, Client: "vnc", Desc: "Screen sharing (display 4)"},
	{Name: "http", Port: 80, Client: "browser", Desc: "Web server"},
	{Name: "https", Port: 443, Client: "browser", Desc: "Web server (TLS)"},
	{Name: "http-alt", Port: 8080, Client: "browser", Desc: "Web server"},
	{Name: "smb", Port: 445, Client: "smb", Desc: "Windows file sharing"},
}

// ClientFor returns the kind of client that connects to a named service.
func ClientFor(name string) string {
	for _, k := range Catalog {
		if k.Name == name {
			return k.Client
		}
	}
	return ""
}

// probeTimeout is per port. Short: everything being probed is on the same
// machine, reached through its own tunnel interface.
const probeTimeout = 700 * time.Millisecond

// DetectServices reports which catalog services are reachable at addr.
//
// It dials the node's *own overlay address* rather than localhost, and that
// distinction is the entire point. A service bound only to 127.0.0.1 is
// invisible to peers, and probing loopback would advertise it anyway — peers
// would see an SSH server they cannot reach. Dialling the overlay address
// tests exactly what a peer would experience.
//
// behind names the ports where what answers on the overlay is LocNet's own
// port-share forwarder, mapped to the address that forwarder connects to.
// Those must be probed at the far end instead, because the forwarder accepts
// whether or not anything is behind it. Skipping that check is how a machine
// with no VNC server at all came to advertise one to the whole network: the
// share published port 5901, the scan dialled it, the forwarder accepted, and
// every peer was told there was a screen here. The connection then closed
// without a byte, which from a VNC client looks like a broken server rather
// than an absent one.
func DetectServices(ctx context.Context, addr netip.Addr, behind map[uint16]string) []Service {
	if !addr.IsValid() {
		return nil
	}

	var (
		mu    sync.Mutex
		found []Service
		wg    sync.WaitGroup
	)
	for _, k := range Catalog {
		wg.Add(1)
		go func(k KnownService) {
			defer wg.Done()
			target := netip.AddrPortFrom(addr, k.Port).String()
			if via, ok := behind[k.Port]; ok {
				target = via
			}

			d := net.Dialer{Timeout: probeTimeout}
			conn, err := d.DialContext(ctx, "tcp", target)
			if err != nil {
				return
			}
			conn.Close()

			// An open port is not a working service. For the ones LocNet
			// opens a client for, speak enough of the protocol to know a
			// login is possible, and say what is wrong when it is not —
			// rather than advertise a screen that refuses everyone.
			svc := Service{Name: k.Name, Port: k.Port}
			svc.Problem = CheckProtocol(ctx, k.Name, target)

			mu.Lock()
			found = append(found, svc)
			mu.Unlock()
		}(k)
	}
	wg.Wait()

	sort.Slice(found, func(i, j int) bool { return found[i].Port < found[j].Port })
	return found
}
