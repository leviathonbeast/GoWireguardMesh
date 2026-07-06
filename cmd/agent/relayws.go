package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// errNoWSRelay means the control plane has no WebSocket relay enabled.
var errNoWSRelay = errors.New("control plane has no websocket relay")

// parseRelayTransport maps the --relay-transport flag to its enum.
func parseRelayTransport(s string) (relayTransport, error) {
	switch s {
	case "websocket", "ws":
		return relayWebSocket, nil
	case "udp":
		return relayUDP, nil
	default:
		return 0, fmt.Errorf("relay-transport must be \"websocket\" or \"udp\", got %q", s)
	}
}

// wsRelayProxy bridges kernel WireGuard to a WebSocket relay path.
//
// Kernel WireGuard can only speak UDP, so the proxy binds a loopback
// UDP socket and the peer's WireGuard endpoint is pointed at it. Every
// datagram the kernel sends there is shipped as one WebSocket message
// to the relay (which rides the control plane's own port, so this
// needs no open ports beyond 443); every message back is written to
// the kernel's socket. The kernel never knows the transport isn't UDP.
//
// This is WireGuard-over-TCP — head-of-line blocking, worse under loss
// — so it is the last-resort path, chosen only after direct and (if
// configured) UDP relay fail.
type wsRelayProxy struct {
	peer  wgtypes.Key
	udp   *net.UDPConn
	ws    *websocket.Conn
	ctx   context.Context
	stop  context.CancelFunc
	wgDst *net.UDPAddr // kernel's source addr, learned from first packet
	mu    sync.Mutex
}

// startWSRelay dials the WebSocket relay for peer, binds a loopback
// UDP socket, points the peer's endpoint at it, and starts pumping.
// The local endpoint is returned so the caller can confirm it in logs.
func (t *telemetryReporter) startWSRelay(peer wgtypes.Key) (*wsRelayProxy, error) {
	wsURL, err := relayWSURL(t.serverURL, peer)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Reuse the agent's HTTP client so a pinned self-signed cert
	// (--server-ca) is trusted for wss:// too.
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: t.client,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + t.authToken}},
	})
	if err != nil {
		cancel()

		if resp != nil && resp.StatusCode == http.StatusServiceUnavailable {
			return nil, errNoWSRelay
		}

		return nil, fmt.Errorf("dial relay ws: %w", err)
	}

	conn.SetReadLimit(1 << 16)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		conn.Close(websocket.StatusInternalError, "")
		cancel()

		return nil, fmt.Errorf("bind loopback udp for relay: %w", err)
	}

	local := udp.LocalAddr().(*net.UDPAddr)

	if err := t.wg.ConfigureDevice(wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  peer,
			UpdateOnly: true,
			Endpoint:   local,
		}},
	}); err != nil {
		udp.Close()
		conn.Close(websocket.StatusInternalError, "")
		cancel()

		return nil, fmt.Errorf("point peer at relay proxy: %w", err)
	}

	p := &wsRelayProxy{peer: peer, udp: udp, ws: conn, ctx: ctx, stop: cancel}

	go p.udpToWS()
	go p.wsToUDP()

	return p, nil
}

// relayWSURL turns the control plane's http(s) URL into the ws(s)
// relay endpoint for a target peer.
func relayWSURL(serverURL string, peer wgtypes.Key) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server url %q: %w", serverURL, err)
	}

	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}

	u.Path = strings.TrimRight(u.Path, "/") + "/relay-ws"
	u.RawQuery = url.Values{"peer": {peer.String()}}.Encode()

	return u.String(), nil
}

func (p *wsRelayProxy) udpToWS() {
	buf := make([]byte, 1<<16)

	for {
		n, src, err := p.udp.ReadFromUDP(buf)
		if err != nil {
			p.stop()
			return
		}

		// The kernel's socket address is the destination for return
		// traffic; it is stable for the life of the tunnel.
		p.mu.Lock()
		p.wgDst = src
		p.mu.Unlock()

		if err := p.ws.Write(p.ctx, websocket.MessageBinary, buf[:n]); err != nil {
			p.stop()
			return
		}
	}
}

func (p *wsRelayProxy) wsToUDP() {
	for {
		_, data, err := p.ws.Read(p.ctx)
		if err != nil {
			p.stop()
			return
		}

		p.mu.Lock()
		dst := p.wgDst
		p.mu.Unlock()

		if dst == nil {
			continue // kernel hasn't sent its first packet yet
		}

		if _, err := p.udp.WriteToUDP(data, dst); err != nil {
			p.stop()
			return
		}
	}
}

func (p *wsRelayProxy) close() {
	p.stop()
	p.udp.Close()
	p.ws.Close(websocket.StatusNormalClosure, "")
}

func (p *wsRelayProxy) endpoint() *net.UDPAddr {
	return p.udp.LocalAddr().(*net.UDPAddr)
}

// alive reports whether the proxy's pumps are still running, so the
// reporter can prune a dead proxy and retry.
func (p *wsRelayProxy) alive() bool {
	select {
	case <-p.ctx.Done():
		return false
	default:
		return true
	}
}
