package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	relayQUICALPN       = "wgmesh-relay/1"
	quicFragmentPayload = 1000
	quicFragmentHeader  = 8
)

type quicRelayProxy struct {
	peer  wgtypes.Key
	udp   *net.UDPConn
	conn  *quic.Conn
	tr    *quic.Transport // owns the outbound (SO_MARK'd) socket
	sock  *net.UDPConn    // the socket tr rides; closed with the proxy
	ctx   context.Context
	stop  context.CancelFunc
	wgDst *net.UDPAddr
	once  sync.Once
	seq   atomic.Uint32
}

type quicRelayAuth struct {
	Token  string `json:"token"`
	Target string `json:"target"`
}

type quicAssembly struct {
	parts [][]byte
	seen  int
	at    time.Time
}

func (t *telemetryReporter) startQUICRelay(peer wgtypes.Key) (*quicRelayProxy, error) {
	endpoint, err := t.requestQUICEndpoint(peer)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, errors.New("control plane has no QUIC relay")
	}

	tlsConfig, err := newPinnedTLSConfig(t.serverCA)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.NextProtos = []string{relayQUICALPN}
	tlsConfig.MinVersion = tls.VersionTLS13

	// A dedicated socket instead of quic.DialAddr's internal one so it
	// can carry the SO_MARK that keeps this relay leg on the underlay
	// when exit-node routing sends default traffic into the tunnel.
	raddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve QUIC relay %q: %w", endpoint, err)
	}
	sock, err := listenUDPMarked("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("bind QUIC relay socket: %w", err)
	}
	tr := &quic.Transport{Conn: sock}

	ctx, cancel := context.WithCancel(context.Background())
	conn, err := tr.Dial(ctx, raddr, tlsConfig, &quic.Config{
		EnableDatagrams:      true,
		KeepAlivePeriod:      20 * time.Second,
		HandshakeIdleTimeout: 10 * time.Second,
	})
	if err != nil {
		cancel()
		tr.Close()
		sock.Close()
		return nil, fmt.Errorf("dial QUIC relay: %w", err)
	}

	// closeDial unwinds everything the dial built, on any later error.
	closeDial := func(code quic.ApplicationErrorCode, msg string) {
		conn.CloseWithError(code, msg)
		cancel()
		tr.Close()
		sock.Close()
	}

	if !conn.ConnectionState().SupportsDatagrams.Remote {
		closeDial(4, "datagrams required")
		return nil, errors.New("QUIC relay did not negotiate datagrams")
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		closeDial(1, "authentication failed")
		return nil, err
	}
	if err := json.NewEncoder(stream).Encode(quicRelayAuth{Token: t.authToken, Target: peer.String()}); err != nil {
		closeDial(1, "authentication failed")
		return nil, err
	}
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	ack, err := bufio.NewReader(io.LimitReader(stream, 16)).ReadString('\n')
	if err != nil || ack != "ok\n" {
		closeDial(1, "authentication failed")
		return nil, errors.New("QUIC relay authentication rejected")
	}
	_ = stream.Close()

	dev, err := t.wg.Device()
	if err != nil || dev.ListenPort == 0 {
		closeDial(0, "closed")
		return nil, errors.New("wireguard device has no listen port yet")
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		closeDial(0, "closed")
		return nil, err
	}
	_ = udp.SetReadBuffer(4 << 20)
	_ = udp.SetWriteBuffer(4 << 20)
	local := udp.LocalAddr().(*net.UDPAddr)
	if err := t.wg.ConfigureDevice(wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey: peer, UpdateOnly: true, Endpoint: local,
	}}}); err != nil {
		udp.Close()
		closeDial(0, "closed")
		return nil, err
	}

	p := &quicRelayProxy{peer: peer, udp: udp, conn: conn, tr: tr, sock: sock, ctx: ctx, stop: cancel,
		wgDst: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dev.ListenPort}}
	go p.udpToQUIC()
	go p.quicToUDP()
	return p, nil
}

func (t *telemetryReporter) requestQUICEndpoint(peer wgtypes.Key) (string, error) {
	body, _ := json.Marshal(map[string]string{"peer_public_key": peer.String()})
	req, err := http.NewRequest(http.MethodPost, t.serverURL+"/relay-quic", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.authToken)
	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("QUIC relay info rejected: %s", resp.Status)
	}
	var out struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return "", err
	}
	return out.Endpoint, nil
}

func (p *quicRelayProxy) udpToQUIC() {
	buf := make([]byte, 1<<16)
	for {
		n, src, err := p.udp.ReadFromUDP(buf)
		if err != nil {
			p.stop()
			return
		}
		if src.Port != p.wgDst.Port || !src.IP.IsLoopback() {
			continue
		}
		id := p.seq.Add(1)
		count := (n + quicFragmentPayload - 1) / quicFragmentPayload
		if count == 0 || count > 255 {
			continue
		}
		for i := 0; i < count; i++ {
			lo := i * quicFragmentPayload
			hi := min(lo+quicFragmentPayload, n)
			frame := make([]byte, quicFragmentHeader+hi-lo)
			frame[0], frame[1], frame[2], frame[3] = 'W', 'Q', byte(i), byte(count)
			binary.BigEndian.PutUint32(frame[4:8], id)
			copy(frame[8:], buf[lo:hi])
			if err := p.conn.SendDatagram(frame); err != nil {
				p.close()
				return
			}
		}
	}
}

func (p *quicRelayProxy) quicToUDP() {
	assemblies := make(map[uint32]*quicAssembly)
	for {
		frame, err := p.conn.ReceiveDatagram(p.ctx)
		if err != nil {
			p.close()
			return
		}
		if len(frame) < quicFragmentHeader || frame[0] != 'W' || frame[1] != 'Q' {
			continue
		}
		idx, count := int(frame[2]), int(frame[3])
		if count == 0 || idx >= count {
			continue
		}
		id := binary.BigEndian.Uint32(frame[4:8])
		a := assemblies[id]
		if a == nil {
			if len(assemblies) >= 64 {
				for old := range assemblies {
					delete(assemblies, old)
					break
				}
			}
			a = &quicAssembly{parts: make([][]byte, count), at: time.Now()}
			assemblies[id] = a
		}
		if len(a.parts) != count || a.parts[idx] != nil {
			continue
		}
		a.parts[idx] = append([]byte(nil), frame[8:]...)
		a.seen++
		if a.seen != count {
			continue
		}
		var packet []byte
		for _, part := range a.parts {
			packet = append(packet, part...)
		}
		delete(assemblies, id)
		if len(packet) <= 1<<16 {
			_, _ = p.udp.WriteToUDP(packet, p.wgDst)
		}
	}
}

func (p *quicRelayProxy) close() {
	p.once.Do(func() {
		p.stop()
		p.udp.Close()
		p.conn.CloseWithError(0, "closed")
		p.tr.Close()
		p.sock.Close()
	})
}
func (p *quicRelayProxy) endpoint() *net.UDPAddr { return p.udp.LocalAddr().(*net.UDPAddr) }
func (p *quicRelayProxy) alive() bool {
	select {
	case <-p.ctx.Done():
		return false
	default:
		return true
	}
}
