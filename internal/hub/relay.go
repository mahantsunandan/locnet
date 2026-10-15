package hub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/disco"
	"github.com/mahantsunandan/locnet/internal/key"
)

const (
	// bindingTTL is how long a relay binding survives without a refresh.
	// Nodes refresh every 20s, so this tolerates several missed refreshes
	// before a node loses its fallback path.
	bindingTTL = 5 * time.Minute
	// sweepInterval is how often expired bindings are dropped.
	sweepInterval = time.Minute
)

type binding struct {
	nodeID string
	addr   netip.AddrPort
	seen   time.Time
}

// Relay forwards packets between nodes that cannot reach each other directly,
// and tells each node what public address it appears to come from.
//
// It is the fallback, not the default. A relayed connection costs a round trip
// through the hub in each direction; a direct one does not. Nodes probe for a
// direct path continuously and abandon the relay as soon as one works, so in a
// healthy network the relay carries the first second of each connection and
// then goes quiet.
//
// The relay cannot read what it forwards. Payloads are WireGuard packets or
// sealed disco boxes, and it holds no key for either.
type Relay struct {
	store *Store
	logf  func(string, ...any)

	mu     sync.Mutex
	pconn  *net.UDPConn
	byWG   map[key.WGPublic]binding
	byNode map[string]netip.AddrPort
}

// NewRelay creates an unstarted relay.
func NewRelay(store *Store, logf func(string, ...any)) *Relay {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Relay{
		store:  store,
		logf:   logf,
		byWG:   make(map[key.WGPublic]binding),
		byNode: make(map[string]netip.AddrPort),
	}
}

// ObservedFor returns the address the relay last saw a node arrive from.
func (r *Relay) ObservedFor(nodeID string) (netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addr, ok := r.byNode[nodeID]
	return addr, ok
}

// Bindings returns how many nodes currently have a relay path.
func (r *Relay) Bindings() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byWG)
}

// ListenAndServe runs the relay until ctx is cancelled.
func (r *Relay) ListenAndServe(ctx context.Context, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("relay: resolve %q: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("relay: listen on %s: %w", addr, err)
	}
	r.mu.Lock()
	r.pconn = pc
	r.mu.Unlock()

	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go r.sweep(ctx)

	r.logf("relay: listening on %s/udp", pc.LocalAddr())

	buf := make([]byte, disco.MaxPacketSize)
	for {
		n, src, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("relay: read: %w", err)
		}
		r.handle(buf[:n], canon(src))
	}
}

func (r *Relay) handle(pkt []byte, src netip.AddrPort) {
	typ, body, err := disco.Type(pkt)
	if err != nil {
		return // not ours; a stray packet on a public UDP port is routine
	}
	switch typ {
	case disco.TypeBind:
		r.handleBind(body, src)
	case disco.TypeForward:
		r.handleForward(body, src)
	}
}

func (r *Relay) handleBind(body []byte, src netip.AddrPort) {
	b, err := disco.ParseBind(body, r.store.MachineKey)
	if err != nil {
		// Unsigned or unknown binds are the expected shape of an attack:
		// without the signature check, anyone could redirect a node's
		// relayed traffic to themselves by binding its key.
		return
	}
	// The bind is signed by the node's identity key, but it claims a
	// WireGuard key too. Check the pairing against what the node registered,
	// so a valid member cannot bind another member's key.
	registered, ok := r.store.NodeByWGKey(b.WGKey)
	if !ok || registered.ID != b.NodeID {
		r.logf("relay: refusing bind from %s: node %q does not own that WireGuard key", src, b.NodeID)
		return
	}

	r.mu.Lock()
	prev, existed := r.byWG[b.WGKey]
	r.byWG[b.WGKey] = binding{nodeID: b.NodeID, addr: src, seen: time.Now()}
	r.byNode[b.NodeID] = src
	pc := r.pconn
	r.mu.Unlock()

	if !existed || prev.addr != src {
		r.logf("relay: %s bound at %s", b.NodeID, src)
	}
	if pc != nil {
		reply := (&disco.BindReply{Nonce: b.Nonce, Observed: src}).Encode()
		_, _ = pc.WriteToUDPAddrPort(reply, src)
	}
}

func (r *Relay) handleForward(body []byte, src netip.AddrPort) {
	dst, from, payload, err := disco.ParseForward(body)
	if err != nil {
		return
	}

	r.mu.Lock()
	sender, senderOK := r.byWG[from]
	target, targetOK := r.byWG[dst]
	pc := r.pconn
	r.mu.Unlock()

	// Only bound nodes may use the relay, and only from the address they
	// bound at. Without this the relay would forward for anyone who could
	// guess two WireGuard public keys.
	if !senderOK || sender.addr != src {
		return
	}
	if !targetOK || pc == nil {
		return // destination has no relay path; the sender will retry
	}
	_, _ = pc.WriteToUDPAddrPort(disco.EncodeForwarded(from, payload), target.addr)
}

func (r *Relay) sweep(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.mu.Lock()
			for k, b := range r.byWG {
				if time.Since(b.seen) > bindingTTL {
					delete(r.byWG, k)
					if r.byNode[b.nodeID] == b.addr {
						delete(r.byNode, b.nodeID)
					}
				}
			}
			r.mu.Unlock()
		}
	}
}

func canon(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}
