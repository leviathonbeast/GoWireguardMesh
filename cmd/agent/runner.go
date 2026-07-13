package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/buildinfo"
	"gowireguard/internal/firewall"
	"gowireguard/internal/proto"
)

type agentRunner struct {
	cfg agentConfig
}

type agentStartupState struct {
	overlayAddr    string
	overlayAddr6   string
	enrolledPeers  []wgtypes.PeerConfig
	gatewayRoutes  []string
	authToken      string
	initialACL     *proto.ACLPolicy
	initialDNS     proto.DNSConfig
	networkPrefix  netip.Prefix
	networkPrefix6 netip.Prefix
	publicEndpoint string   // startup STUN result, "" if unavailable
	stunServers    []string // mesh STUN endpoints from enrollment
	listenPort     int
}

func (r *agentRunner) run(stop <-chan struct{}) error {
	if err := setupLogging(r.cfg.LogLevel); err != nil {
		return err
	}
	slog.Info("wgmesh agent starting", "git_commit", buildinfo.Commit())

	mode, err := parseDNSMode(r.cfg.DNSMode)
	if err != nil {
		return err
	}
	dnsApplyMode = mode

	if err := ensurePrivileged(); err != nil {
		return err
	}

	// Cleanup stale interface if present.
	if err := deleteInterface(ifaceName); err != nil {
		return err
	}

	// A previous run that took over /etc/resolv.conf and crashed left the
	// takeover in place; put the original back before this run decides
	// whether to apply DNS again.
	if err := restoreResolvConf(); err != nil {
		slog.Warn("stale resolv.conf restore failed", "error", err)
	}

	privateKey, err := loadOrGenerateKey(r.cfg.KeyFile)
	if err != nil {
		return err
	}

	listenPort, err := resolveListenPort(r.cfg.ListenPort, r.cfg.KeyFile+".port")
	if err != nil {
		return err
	}

	agentPrintf("[agent] public key: %s\n", privateKey.PublicKey())
	agentPrintf("[agent] using listen port: %d\n", listenPort)

	statusPub.update(func(s *agentStatus) {
		s.PublicKey = privateKey.PublicKey().String()
		s.ListenPort = listenPort
		s.Server = r.cfg.Server
	})

	cleanupFirewall := r.openFirewall(listenPort)
	defer cleanupFirewall()

	state, err := r.startupStateRetry(privateKey, listenPort, stop)
	if err != nil {
		return err
	}

	defer func() {
		if err := deleteInterface(ifaceName); err != nil {
			slog.Error("interface cleanup failed", "error", err)
		}
	}()

	// resolved-applied DNS dies with the link above; a resolv.conf
	// takeover outlives the process and needs an explicit revert.
	defer func() {
		if err := restoreResolvConf(); err != nil {
			slog.Warn("resolv.conf restore failed", "error", err)
		}
	}()

	if err := r.setupInterface(state.overlayAddr, state.overlayAddr6, state.initialDNS); err != nil {
		return err
	}

	backend, err := newWGBackend(ifaceName)
	if err != nil {
		return err
	}
	defer backend.Close()

	peers, err := r.initialPeers(state.enrolledPeers)
	if err != nil {
		return err
	}

	if err := backend.ConfigureDevice(wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        peers,
	}); err != nil {
		return err
	}

	if state.initialACL != nil {
		if err := applyOverlayACL(ifaceName, state.initialACL); err != nil {
			slog.Warn("initial overlay acl sync failed", "error", err)
		}
	}

	cleanupGatewayNAT, err := enableGatewayNAT(ifaceName, r.cfg.GatewayNATCIDRs)
	if err != nil {
		return err
	}
	defer cleanupGatewayNAT()

	// Route-based mobile gateways: enable forwarding (no NAT) up front so
	// a mobile peer already pinned to this agent is reachable before the
	// first /report. The reporter keeps this in sync thereafter and tears
	// the FORWARD rules down when it stops.
	gatewayForwardOn := false
	if err := applyGatewayRoutes(ifaceName, state.gatewayRoutes, &gatewayForwardOn); err != nil {
		slog.Warn("initial gateway route forwarding failed", "error", err)
	}

	agentPrintf("[agent] wireguard interface setup complete\n")
	agentPrintf("[agent] direct peer connectivity requires each peer to reach the configured endpoint over UDP\n")

	reporterStop, err := r.startReporter(backend, state)
	if err != nil {
		return err
	}

	statusPub.update(func(s *agentStatus) {
		s.State = stateRunning
		s.OverlayAddr = state.overlayAddr
		s.OverlayAddr6 = state.overlayAddr6
	})

	waitForShutdown(stop)

	statusPub.update(func(s *agentStatus) { s.State = stateStopping })

	if reporterStop != nil {
		close(reporterStop)
	}

	return nil
}

func (r *agentRunner) openFirewall(listenPort int) func() {
	if !r.cfg.ManageFirewall {
		return func() {}
	}

	fw, err := firewall.OpenWithReconcile("wgmesh-agent", r.cfg.KeyFile+".fw")
	if err != nil {
		slog.Warn("firewall unavailable; open the port yourself if needed", "error", err, "udp", listenPort)
		return func() {}
	}

	if err := fw.AllowUDP(listenPort); err != nil {
		slog.Warn("firewall rule failed", "backend", fw.Backend(), "error", err)
	} else {
		agentPrintf("[agent] firewall (%s): opened udp %d\n", fw.Backend(), listenPort)
	}

	return func() {
		if err := fw.Close(); err != nil {
			slog.Warn("firewall cleanup failed", "error", err)
		}
	}
}

const (
	startupRetryMin = 2 * time.Second
	startupRetryMax = time.Minute
)

// startupStateRetry retries transient startup failures — control plane
// not up yet, DNS not ready, STUN unreachable — with capped exponential
// backoff instead of exiting: a docker-sidecar'd agent routinely boots
// before the server it enrolls with, and a crash-loop through the
// container restart policy is just this loop with worse logging.
// Permanent rejections (bad or revoked setup key) still fail fast.
func (r *agentRunner) startupStateRetry(privateKey wgtypes.Key, listenPort int, stop <-chan struct{}) (agentStartupState, error) {
	delay := startupRetryMin

	for {
		state, err := r.startupState(privateKey, listenPort)
		if err == nil || isPermanentStartupErr(err) {
			return state, err
		}

		slog.Warn("startup failed; retrying", "error", err, "retry_in", delay)

		select {
		case <-stop:
			return agentStartupState{}, fmt.Errorf("stopped while retrying startup: %w", err)
		case <-time.After(delay):
		}

		delay = min(delay*2, startupRetryMax)
	}
}

// isPermanentStartupErr reports whether retrying cannot help: the
// server understood the request and refused it. 408/429 stay
// retryable; so do network errors and 5xx, which carry no verdict.
func isPermanentStartupErr(err error) bool {
	if errors.Is(err, errSetupKeyRequired) {
		return true
	}

	var rejected *enrollRejectedError
	if errors.As(err, &rejected) {
		return rejected.status >= 400 && rejected.status < 500 &&
			rejected.status != http.StatusRequestTimeout &&
			rejected.status != http.StatusTooManyRequests
	}

	return false
}

var errSetupKeyRequired = errors.New("--setup-key is required with --server")

func (r *agentRunner) startupState(privateKey wgtypes.Key, listenPort int) (agentStartupState, error) {
	state := agentStartupState{
		overlayAddr:  r.cfg.Addr,
		overlayAddr6: r.cfg.Addr6,
	}

	if r.cfg.Server == "" {
		return state, nil
	}

	if r.cfg.SetupKey == "" {
		return state, errSetupKeyRequired
	}

	hostname := agentHostname(r.cfg.Hostname)
	publicEndpoint, err := r.discoverPublicEndpoint(listenPort)
	if err != nil {
		return state, err
	}

	effectivePort := effectiveListenPort(r.cfg.ListenPort, listenPort)

	// Host candidates gathered before the interface exists — nothing to
	// exclude yet beyond the built-in filters; overlay prefixes are only
	// assigned after enrollment.
	resp, err := enroll(
		r.cfg.Server,
		r.cfg.SetupKey,
		r.cfg.ServerCA,
		privateKey.PublicKey(),
		hostname,
		effectivePort,
		publicEndpoint,
		gatherLocalCandidates(effectivePort),
	)
	if err != nil {
		return state, err
	}

	state.authToken = resp.AuthToken
	state.initialACL = resp.ACL
	state.initialDNS = resp.DNS
	state.gatewayRoutes = resp.GatewayRoutes
	state.publicEndpoint = publicEndpoint
	state.stunServers = resp.STUNServers
	state.listenPort = effectivePort

	state.networkPrefix, err = netip.ParsePrefix(resp.NetworkCIDR)
	if err != nil {
		return state, fmt.Errorf("parse network CIDR %q from server: %w", resp.NetworkCIDR, err)
	}

	state.overlayAddr, err = overlayAddress(resp.AssignedIP, state.networkPrefix)
	if err != nil {
		return state, err
	}

	if resp.NetworkCIDR6 != "" {
		state.networkPrefix6, err = netip.ParsePrefix(resp.NetworkCIDR6)
		if err != nil {
			return state, fmt.Errorf("parse IPv6 network CIDR %q from server: %w", resp.NetworkCIDR6, err)
		}

		state.overlayAddr6, err = overlayAddress(resp.AssignedIP6, state.networkPrefix6)
		if err != nil {
			return state, err
		}
	}

	for _, p := range resp.Peers {
		cfg, err := peerConfigFromProto(p)
		if err != nil {
			return state, err
		}

		state.enrolledPeers = append(state.enrolledPeers, cfg)
	}

	assigned := state.overlayAddr
	if state.overlayAddr6 != "" {
		assigned += ", " + state.overlayAddr6
	}

	agentPrintf("[agent] enrolled as peer %d, assigned %s, %d peer(s) in mesh\n", resp.PeerID, assigned, len(resp.Peers))

	return state, nil
}

func (r *agentRunner) discoverPublicEndpoint(listenPort int) (string, error) {
	if r.cfg.STUNServer == "" {
		return "", nil
	}

	publicEndpoint, err := discoverPublicEndpoint(r.cfg.STUNServer, listenPort)
	if err != nil {
		slog.Warn("stun discovery failed; continuing without public endpoint", "error", err)
		return "", nil
	}

	agentPrintf("[agent] stun public endpoint: %s\n", publicEndpoint)

	return publicEndpoint, nil
}

func (r *agentRunner) setupInterface(overlayAddr, overlayAddr6 string, initialDNS proto.DNSConfig) error {
	if err := createInterface(ifaceName); err != nil {
		return err
	}

	if err := assignIPAddress(ifaceName, overlayAddr); err != nil {
		return err
	}

	if overlayAddr6 != "" {
		if err := assignIPAddress(ifaceName, overlayAddr6); err != nil {
			return err
		}
	}

	if err := bringInterfaceUp(ifaceName); err != nil {
		return err
	}

	if initialDNS.Enabled {
		if err := applyDNSConfig(ifaceName, initialDNS); err != nil {
			if errors.Is(err, errDNSUnsupported) {
				slog.Warn("initial dns sync not applied; configure DNS manually", "error", err)
				return nil
			}
			slog.Warn("initial dns sync failed", "error", err)
		}
	}

	return nil
}

func (r *agentRunner) initialPeers(enrolledPeers []wgtypes.PeerConfig) ([]wgtypes.PeerConfig, error) {
	peers := append([]wgtypes.PeerConfig(nil), enrolledPeers...)

	if r.cfg.PeerKey == "" {
		return peers, nil
	}
	if r.cfg.PeerAddr == "" {
		return nil, errors.New("peer-addr is required when peer-key is set")
	}

	peerCfg, err := buildPeerConfig(
		r.cfg.PeerKey,
		r.cfg.PeerEndpoint,
		r.cfg.PeerAddr,
		r.cfg.PeerAddr6,
		r.cfg.PeerPSK,
	)
	if err != nil {
		return nil, err
	}

	return append(peers, peerCfg), nil
}

func (r *agentRunner) startReporter(backend wgBackend, state agentStartupState) (chan struct{}, error) {
	if state.authToken == "" {
		return nil, nil
	}

	transport, err := parseRelayTransport(r.cfg.RelayTransport)
	if err != nil {
		return nil, err
	}

	reporter, err := newTelemetryReporter(
		backend,
		r.cfg.Server,
		state.authToken,
		r.cfg.ServerCA,
		ifaceName,
		state.overlayAddr,
		state.overlayAddr6,
		state.networkPrefix,
		state.networkPrefix6,
		r.cfg.ReportInterval,
		transport,
		r.cfg.DirectProbe,
		r.cfg.GatewayNATCIDRs,
	)
	if err != nil {
		slog.Error("telemetry init failed", "error", err)
		return nil, nil
	}

	// NAT-traversal state for the reporter: the startup STUN result and
	// listen port seed the endpoint refresh loop; mesh STUN endpoints
	// (when the control plane runs the embedded relay) take over from
	// the public fallback for periodic re-checks and NAT classification.
	reporter.listenPort = state.listenPort
	reporter.publicEndpoint = state.publicEndpoint
	reporter.stunFallback = r.cfg.STUNServer
	reporter.stunServers = state.stunServers

	if r.cfg.PortMapping {
		reporter.portMapper = newPortMapper(state.listenPort)
	}

	if r.cfg.TraefikAccessLog != "" {
		reporter.proxyTail = newProxyTailer(r.cfg.TraefikAccessLog)
		agentPrintf("[agent] ingesting Traefik access log %s\n", r.cfg.TraefikAccessLog)
	}

	stop := make(chan struct{})
	go reporter.run(stop)
	agentPrintf("[agent] telemetry reporting enabled every %s\n", r.cfg.ReportInterval)

	return stop, nil
}
