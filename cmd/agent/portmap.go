package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	natpmp "github.com/jackpal/go-nat-pmp"
)

// Router port mapping (UPnP IGD / NAT-PMP) makes this agent's
// WireGuard port directly reachable, converting pairs that would
// otherwise need hole punching or relay into plain direct connections.
//
// Exposing a port automatically is a security-sensitive act, so the
// mapper is deliberately narrow:
//
//   - It only ever maps THIS agent's WireGuard listen port, UDP only,
//     to this host. There is no API surface to map anything else.
//   - The exposed service is WireGuard itself: authenticated by
//     cryptokey routing and silent to unauthenticated probes, which is
//     what makes automating the hole acceptable at all.
//   - Mappings are lease-limited (30 min) and renewed while the agent
//     runs; if the agent dies, the hole closes itself. Shutdown
//     deletes the mapping outright.
//   - The internal client is pinned to the specific local address
//     facing the gateway — never a wildcard.
//   - Mappings are labeled "wgmesh-agent" so they are attributable in
//     the router's UI.
//   - A private/CGNAT external IP (double NAT) means the mapping does
//     not actually reach the internet: it is deleted again rather than
//     advertised as a candidate.
//   - NAT-PMP talks only to the default gateway, never a configurable
//     address, so the agent cannot be steered into probing third
//     parties.
//   - --port-mapping=false turns the whole subsystem off.
const (
	portMapLease     = 30 * time.Minute
	portMapRenew     = portMapLease / 2
	portMapRetryMin  = 5 * time.Minute
	portMapRetryMax  = time.Hour
	portMapAttemptTO = 15 * time.Second
)

// portMapper maintains one router mapping for the WireGuard listen
// port and exposes the resulting external endpoint as a candidate.
type portMapper struct {
	port int
	stop chan struct{}
	done chan struct{}

	mu  sync.Mutex
	ext string // router's external "ip:port" for us; "" when unmapped
}

func newPortMapper(port int) *portMapper {
	m := &portMapper{
		port: port,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	go m.run()

	return m
}

// external returns the current router-mapped endpoint, "" when none.
func (m *portMapper) external() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.ext
}

func (m *portMapper) setExternal(ep string) {
	m.mu.Lock()
	changed := m.ext != ep
	m.ext = ep
	m.mu.Unlock()

	if changed && ep != "" {
		fmt.Printf("[agent] router mapped udp %s -> local port %d\n", ep, m.port)
	}
}

// close stops renewal and removes the mapping from the router.
func (m *portMapper) close() {
	close(m.stop)
	<-m.done
}

// run maps, renews at half-lease, and backs off (5m..1h) while no
// router cooperates — a host that is not behind a NAT, or whose router
// has UPnP disabled, costs a couple of multicast packets an hour.
func (m *portMapper) run() {
	defer close(m.done)

	retry := portMapRetryMin

	var unmap func()

	for {
		ep, um, err := mapPort(m.port)
		wait := portMapRenew

		if err != nil {
			slog.Debug("port mapping unavailable", "error", err)
			m.setExternal("")
			unmap = nil
			wait = retry
			retry = min(retry*2, portMapRetryMax)
		} else {
			m.setExternal(ep)
			unmap = um
			retry = portMapRetryMin
		}

		select {
		case <-m.stop:
			if unmap != nil {
				unmap()
			}
			return
		case <-time.After(wait):
		}
	}
}

// mapPort tries UPnP IGD first (the common consumer-router case), then
// NAT-PMP toward the default gateway. Returns the external endpoint
// and an unmap function for shutdown.
func mapPort(port int) (string, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), portMapAttemptTO)
	defer cancel()

	if ep, unmap, err := upnpMap(ctx, port); err == nil {
		return ep, unmap, nil
	} else {
		slog.Debug("upnp mapping failed", "error", err)
	}

	ep, unmap, err := natpmpMap(port)
	if err != nil {
		return "", nil, err
	}

	return ep, unmap, nil
}

// igdConn adapts the three IGD service revisions goupnp generates to
// the one call pattern we use. All three share identical signatures.
type igdConn struct {
	name  string
	host  string // IGD's control URL host:port, for local-IP discovery
	getIP func() (string, error)
	add   func(extPort, intPort uint16, intClient string, leaseSecs uint32) error
	del   func(extPort uint16) error
}

func upnpMap(ctx context.Context, port int) (string, func(), error) {
	conns := discoverIGD(ctx)
	if len(conns) == 0 {
		return "", nil, fmt.Errorf("no UPnP internet gateway found")
	}

	var lastErr error

	for _, c := range conns {
		extIP, err := c.getIP()
		if err != nil {
			lastErr = fmt.Errorf("%s external ip: %w", c.name, err)
			continue
		}

		ext, err := netip.ParseAddr(extIP)
		if err != nil || !publicV4(ext) {
			// Double NAT: the "external" side is itself private, so a
			// mapping here never reaches the internet. Don't hold a
			// useless hole open.
			lastErr = fmt.Errorf("%s external ip %q is not public (double NAT?)", c.name, extIP)
			continue
		}

		localIP, err := localAddrToward(c.host)
		if err != nil {
			lastErr = err
			continue
		}

		if err := c.add(uint16(port), uint16(port), localIP, uint32(portMapLease.Seconds())); err != nil {
			lastErr = fmt.Errorf("%s add mapping: %w", c.name, err)
			continue
		}

		del := c.del
		unmap := func() {
			if err := del(uint16(port)); err != nil {
				slog.Debug("upnp unmap failed", "error", err)
			}
		}

		return net.JoinHostPort(extIP, strconv.Itoa(port)), unmap, nil
	}

	return "", nil, lastErr
}

// discoverIGD collects candidate IGD control clients, newest service
// revision first. Discovery errors are per-device and non-fatal.
func discoverIGD(ctx context.Context) []igdConn {
	var out []igdConn

	wrap := func(name string, sc goupnp.ServiceClient,
		getIP func() (string, error),
		add func(string, uint16, string, uint16, string, bool, string, uint32) error,
		del func(string, uint16, string) error,
	) {
		out = append(out, igdConn{
			name:  name,
			host:  sc.Location.Host,
			getIP: getIP,
			add: func(extPort, intPort uint16, intClient string, leaseSecs uint32) error {
				return add("", extPort, "UDP", intPort, intClient, true, "wgmesh-agent", leaseSecs)
			},
			del: func(extPort uint16) error {
				return del("", extPort, "UDP")
			},
		})
	}

	if cs, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			wrap("WANIPConnection2", c.ServiceClient, c.GetExternalIPAddress, c.AddPortMapping, c.DeletePortMapping)
		}
	}
	if cs, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			wrap("WANIPConnection1", c.ServiceClient, c.GetExternalIPAddress, c.AddPortMapping, c.DeletePortMapping)
		}
	}
	if cs, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			wrap("WANPPPConnection1", c.ServiceClient, c.GetExternalIPAddress, c.AddPortMapping, c.DeletePortMapping)
		}
	}

	return out
}

func natpmpMap(port int) (string, func(), error) {
	gw := defaultGatewayIP()
	if gw == nil {
		return "", nil, fmt.Errorf("no default gateway for NAT-PMP")
	}

	client := natpmp.NewClientWithTimeout(gw, 3*time.Second)

	ext, err := client.GetExternalAddress()
	if err != nil {
		return "", nil, fmt.Errorf("nat-pmp external address: %w", err)
	}

	extIP := netip.AddrFrom4(ext.ExternalIPAddress)
	if !publicV4(extIP) {
		return "", nil, fmt.Errorf("nat-pmp external ip %s is not public (double NAT?)", extIP)
	}

	res, err := client.AddPortMapping("udp", port, port, int(portMapLease.Seconds()))
	if err != nil {
		return "", nil, fmt.Errorf("nat-pmp add mapping: %w", err)
	}

	extPort := int(res.MappedExternalPort)

	unmap := func() {
		// NAT-PMP delete = request the mapping with lifetime 0.
		if _, err := client.AddPortMapping("udp", port, 0, 0); err != nil {
			slog.Debug("nat-pmp unmap failed", "error", err)
		}
	}

	return net.JoinHostPort(extIP.String(), strconv.Itoa(extPort)), unmap, nil
}

// localAddrToward returns this host's address on the interface that
// routes toward host — the address the router must forward to. The
// dial sends nothing (UDP connect only sets the route).
func localAddrToward(host string) (string, error) {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "1900")
	}

	conn, err := net.Dial("udp4", host)
	if err != nil {
		return "", fmt.Errorf("resolve local address toward gateway: %w", err)
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// publicV4 reports whether ip is a v4 address reachable from the
// internet — i.e. worth advertising as a router-mapped candidate.
func publicV4(ip netip.Addr) bool {
	ip = ip.Unmap()

	return ip.Is4() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsMulticast() && !ip.IsUnspecified() && !cgnat.Contains(ip)
}
