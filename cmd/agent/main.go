package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/firewall"
	"gowireguard/internal/proto"
)

const (
	ifaceName = "wg-int"
	//listenPort = 51820
)

var (
	listenPortFlag = flag.Int(
		"listen-port",
		0,
		"WireGuard UDP listen port (0 = auto-select a free port)",
	)
)

var (
	addrFlag           = flag.String("addr", "100.64.0.1/16", "overlay address (CIDR)")
	addr6Flag          = flag.String("addr6", "", "optional IPv6 overlay address (CIDR)")
	peerKeyFlag        = flag.String("peer-key", "", "peer public key (base64)")
	peerEndpointFlag   = flag.String("peer-endpoint", "", "peer endpoint host:port (optional)")
	peerAddrFlag       = flag.String("peer-addr", "", "peer overlay address, e.g. 100.64.0.2/32")
	peerAddr6Flag      = flag.String("peer-addr6", "", "optional peer IPv6 overlay address, e.g. fd00:100:64::2/128")
	peerPSKFlag        = flag.String("peer-psk", "", "preshared key (base64, optional)")
	serverFlag         = flag.String("server", "", "control plane URL (e.g. https://host:8080); enables enrollment mode")
	setupKeyFlag       = flag.String("setup-key", "", "setup key for enrollment (required with --server)")
	hostnameFlag       = flag.String("hostname", os.Getenv("WGMESH_HOSTNAME"), "name to show in the control plane (defaults to OS hostname; can also be set with WGMESH_HOSTNAME)")
	serverCAFlag       = flag.String("server-ca", "", "PEM certificate to trust for the control plane (pin its self-signed cert.pem)")
	reportIntervalFlag = flag.Duration("report-interval", 30*time.Second, "telemetry reporting interval")
	stunServerFlag     = flag.String("stun-server", "stun.l.google.com:19302", "STUN server for public endpoint discovery (empty disables)")
	relayTransportFlag = flag.String("relay-transport", "websocket", "relay fallback transport: \"websocket\" (rides the control-plane port, needs no extra firewall holes) or \"udp\" (faster, needs the relay port range reachable)")
	manageFirewallFlag = flag.Bool("manage-firewall", true, "open the WireGuard listen port on the host firewall (removed again on shutdown)")
	keyFileFlag        = flag.String("key-file", "wgkey.key", "path to private key file")
	logLevelFlag       = flag.String("log-level", "info", "minimum log level: debug, info, warn, or error")
)

// setupLogging installs the process-wide slog handler. Human status
// output (public key, enrollment result) stays on stdout via
// fmt.Printf; slog carries warnings, errors, and per-tick debug
// chatter on stderr.
func setupLogging(level string) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf(`log-level must be "debug", "info", "warn", or "error", got %q`, level)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))

	return nil
}

func waitForShutdown(stop <-chan struct{}) {
	sigCh := make(chan os.Signal, 1)

	signal.Notify(
		sigCh,
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer signal.Stop(sigCh)

	fmt.Println("\nWaiting for shutdown signal (Ctrl+C)...")

	select {
	case sig := <-sigCh:
		fmt.Printf("\nReceived signal: %s\n", sig)
	case <-stop:
		fmt.Println("\nReceived service stop request")
	}
}

func run() error {
	return runWithStop(nil)
}

func buildPeerConfig(
	pubkey,
	endpoint,
	allowedCIDR,
	allowedCIDR6,
	presharedKey string,
) (wgtypes.PeerConfig, error) {
	publicKey, err := wgtypes.ParseKey(pubkey)
	if err != nil {
		return wgtypes.PeerConfig{},
			fmt.Errorf("parse public key %q: %w", pubkey, err)
	}

	var udpAddr *net.UDPAddr

	if endpoint != "" {
		udpAddr, err = net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return wgtypes.PeerConfig{},
				fmt.Errorf("resolve endpoint %q: %w", endpoint, err)
		}
	}

	_, allowedNet, err := net.ParseCIDR(allowedCIDR)
	if err != nil {
		return wgtypes.PeerConfig{},
			fmt.Errorf("parse allowed CIDR %q: %w", allowedCIDR, err)
	}

	allowed := []net.IPNet{*allowedNet}
	if allowedCIDR6 != "" {
		_, allowedNet6, err := net.ParseCIDR(allowedCIDR6)
		if err != nil {
			return wgtypes.PeerConfig{},
				fmt.Errorf("parse IPv6 allowed CIDR %q: %w", allowedCIDR6, err)
		}
		allowed = append(allowed, *allowedNet6)
	}

	var psk *wgtypes.Key

	if presharedKey != "" {
		key, err := wgtypes.ParseKey(presharedKey)
		if err != nil {
			return wgtypes.PeerConfig{},
				fmt.Errorf("parse preshared key: %w", err)
		}

		psk = &key
	}

	keepalive := 25 * time.Second

	cfg := wgtypes.PeerConfig{
		PublicKey:                   publicKey,
		Endpoint:                    udpAddr,
		PresharedKey:                psk,
		AllowedIPs:                  allowed,
		PersistentKeepaliveInterval: &keepalive,
	}

	return cfg, nil
}

func resolveListenPort(preferred int, portFile string) (int, error) {
	if portFile != "" {
		if data, err := os.ReadFile(portFile); err == nil {
			if port, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && port > 0 && port <= 65535 {
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
				if err == nil {
					localPort := conn.LocalAddr().(*net.UDPAddr).Port
					_ = conn.Close()
					return localPort, nil
				}
			}
		}
	}

	if preferred > 0 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: preferred})
		if err == nil {
			port := conn.LocalAddr().(*net.UDPAddr).Port
			_ = conn.Close()
			return port, nil
		}
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return 0, fmt.Errorf("find available udp port: %w", err)
	}
	defer conn.Close()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	if portFile != "" {
		if err := os.WriteFile(portFile, []byte(strconv.Itoa(port)+"\n"), 0600); err != nil {
			return 0, fmt.Errorf("write listen-port file %q: %w", portFile, err)
		}
	}

	return port, nil
}

func loadOrGenerateKey(path string) (wgtypes.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Generate a new private key
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return wgtypes.Key{}, fmt.Errorf("generate private key: %w", err)
			}

			// Save it to disk with secure permissions
			err = os.WriteFile(path, []byte(key.String()+"\n"), 0600)
			if err != nil {
				return wgtypes.Key{}, fmt.Errorf("write key file %q: %w", path, err)
			}

			return key, nil
		}

		return wgtypes.Key{}, fmt.Errorf("read key file %q: %w", path, err)
	}

	// Parse existing key
	keyStr := strings.TrimSpace(string(data))

	key, err := wgtypes.ParseKey(keyStr)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("parse key file %q: %w", path, err)
	}

	return key, nil
}

// newHTTPClient returns a client trusting caFile (a PEM certificate,
// typically the control plane's self-signed cert) in addition to
// nothing else — pinning replaces the system pool rather than adding
// to it. An empty caFile means the system pool.
func newHTTPClient(caFile string) (*http.Client, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	if caFile == "" {
		return client, nil
	}

	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read server CA file %q: %w", caFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("server CA file %q contains no valid PEM certificates", caFile)
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}

	return client, nil
}

// enroll registers this node with the control plane and returns the
// mesh configuration. Never sends the private key.
func enroll(serverURL, setupKey, serverCA string, publicKey wgtypes.Key, hostname string, listenPort int, publicEndpoint string) (*proto.EnrollResponse, error) {
	reqBody, err := json.Marshal(proto.EnrollRequest{
		SetupKey:       setupKey,
		PublicKey:      publicKey.String(),
		Hostname:       hostname,
		ListenPort:     listenPort,
		PublicEndpoint: publicEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("encode enroll request: %w", err)
	}

	client, err := newHTTPClient(serverCA)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(serverURL+"/enroll", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("post enroll to %q: %w", serverURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read enroll response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll rejected: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out proto.EnrollResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode enroll response: %w", err)
	}

	return &out, nil
}

// peerConfigFromProto converts a wire-format peer entry into the
// wgtypes.PeerConfig handed to ConfigureDevice.
func peerConfigFromProto(p proto.PeerConfigResponse) (wgtypes.PeerConfig, error) {
	publicKey, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parse peer public key %q: %w", p.PublicKey, err)
	}

	var udpAddr *net.UDPAddr

	endpoint := ""
	if len(p.EndpointCandidates) > 0 {
		endpoint = p.EndpointCandidates[0].Endpoint
	} else if p.Endpoint != nil {
		endpoint = *p.Endpoint
	}

	if endpoint != "" {
		udpAddr, err = net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("resolve endpoint %q: %w", endpoint, err)
		}
	}

	allowed := make([]net.IPNet, 0, len(p.AllowedIPs))

	for _, cidr := range p.AllowedIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("parse allowed CIDR %q: %w", cidr, err)
		}

		allowed = append(allowed, *ipnet)
	}

	var psk *wgtypes.Key

	if p.PresharedKey != nil {
		key, err := wgtypes.ParseKey(*p.PresharedKey)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("parse preshared key: %w", err)
		}

		psk = &key
	}

	var keepalive *time.Duration

	if p.PersistentKeepaliveInterval != nil {
		d := time.Duration(*p.PersistentKeepaliveInterval) * time.Second
		keepalive = &d
	}

	return wgtypes.PeerConfig{
		PublicKey:                   publicKey,
		Endpoint:                    udpAddr,
		PresharedKey:                psk,
		AllowedIPs:                  allowed,
		PersistentKeepaliveInterval: keepalive,
	}, nil
}

// overlayAddress combines the assigned IP with the mesh network's
// prefix length. The interface address MUST carry the network prefix
// (/16), not /32: the connected route it creates is the only thing
// steering 100.64.0.0/16 traffic into wg-int. With /32 the kernel has
// no route to other peers, so overlay-bound packets leak out the
// default LAN route with an underlay source address — observed as
// icmp flows like "10.0.40.x -> 100.64.0.x" that never get replies.
// Reachability within the /16 is still enforced by cryptokey routing
// (ENOKEY) and server-side ACL visibility.
func overlayAddress(addr string, network netip.Prefix) (string, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf("parse overlay address %q: %w", addr, err)
	}

	return fmt.Sprintf("%s/%d", ip, network.Bits()), nil
}

func effectiveListenPort(flagPort, resolvedPort int) int {
	if resolvedPort > 0 {
		return resolvedPort
	}

	return flagPort
}

func agentHostname(override string) string {
	if name := strings.TrimSpace(override); name != "" {
		return name
	}

	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(hostname)
}

func runWithStop(stop <-chan struct{}) error {
	flag.Parse()

	if err := setupLogging(*logLevelFlag); err != nil {
		return err
	}

	if err := ensurePrivileged(); err != nil {
		return err
	}

	// Cleanup stale interface if present.
	if err := deleteInterface(ifaceName); err != nil {
		return err
	}

	privateKey, err := loadOrGenerateKey(*keyFileFlag)
	if err != nil {
		return err
	}

	listenPort, err := resolveListenPort(*listenPortFlag, *keyFileFlag+".port")
	if err != nil {
		return err
	}

	fmt.Printf("[agent] public key: %s\n", privateKey.PublicKey())
	fmt.Printf("[agent] using listen port: %d\n", listenPort)

	if *manageFirewallFlag {
		fw, err := firewall.OpenWithReconcile("wgmesh-agent", *keyFileFlag+".fw")
		if err != nil {
			slog.Warn("firewall unavailable; open the port yourself if needed", "error", err, "udp", listenPort)
		} else {
			if err := fw.AllowUDP(listenPort); err != nil {
				slog.Warn("firewall rule failed", "backend", fw.Backend(), "error", err)
			} else {
				fmt.Printf("[agent] firewall (%s): opened udp %d\n", fw.Backend(), listenPort)
			}

			defer func() {
				if err := fw.Close(); err != nil {
					slog.Warn("firewall cleanup failed", "error", err)
				}
			}()
		}
	}

	// Enrollment mode: the control plane dictates our overlay address
	// and peer list; the manual --peer-* flags are the standalone path.
	overlayAddr := *addrFlag
	overlayAddr6 := *addr6Flag

	var (
		enrolledPeers  []wgtypes.PeerConfig
		authToken      string
		networkPrefix  netip.Prefix
		networkPrefix6 netip.Prefix
	)

	if *serverFlag != "" {
		if *setupKeyFlag == "" {
			return errors.New("--setup-key is required with --server")
		}

		hostname := agentHostname(*hostnameFlag)

		// STUN must run before the interface exists so the probe can
		// bind the WireGuard port and discover its public mapping.
		var publicEndpoint string

		if *stunServerFlag != "" {
			publicEndpoint, err = discoverPublicEndpoint(
				*stunServerFlag,
				listenPort,
			)

			if err != nil {
				slog.Warn("stun discovery failed; continuing without public endpoint", "error", err)
			} else {
				fmt.Printf(
					"[agent] stun public endpoint: %s\n",
					publicEndpoint,
				)
			}
		}

		resp, err := enroll(
			*serverFlag,
			*setupKeyFlag,
			*serverCAFlag,
			privateKey.PublicKey(),
			hostname,
			effectiveListenPort(*listenPortFlag, listenPort),
			publicEndpoint,
		)
		if err != nil {
			return err
		}

		authToken = resp.AuthToken

		networkPrefix, err = netip.ParsePrefix(resp.NetworkCIDR)
		if err != nil {
			return fmt.Errorf(
				"parse network CIDR %q from server: %w",
				resp.NetworkCIDR,
				err,
			)
		}

		overlayAddr, err = overlayAddress(resp.AssignedIP, networkPrefix)
		if err != nil {
			return err
		}

		if resp.NetworkCIDR6 != "" {
			networkPrefix6, err = netip.ParsePrefix(resp.NetworkCIDR6)
			if err != nil {
				return fmt.Errorf(
					"parse IPv6 network CIDR %q from server: %w",
					resp.NetworkCIDR6,
					err,
				)
			}

			overlayAddr6, err = overlayAddress(resp.AssignedIP6, networkPrefix6)
			if err != nil {
				return err
			}
		}

		for _, p := range resp.Peers {
			cfg, err := peerConfigFromProto(p)
			if err != nil {
				return err
			}

			enrolledPeers = append(enrolledPeers, cfg)
		}

		assigned := overlayAddr
		if overlayAddr6 != "" {
			assigned += ", " + overlayAddr6
		}

		fmt.Printf("[agent] enrolled as peer %d, assigned %s, %d peer(s) in mesh\n", resp.PeerID, assigned, len(resp.Peers))
	}

	defer func() {
		if err := deleteInterface(ifaceName); err != nil {
			slog.Error("interface cleanup failed", "error", err)
		}
	}()

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

	// One WireGuard backend serves both the initial configuration and
	// the reporter loop: kernel WireGuard via wgctrl on Linux, the
	// embedded wireguard-go device via its in-process UAPI on Windows.
	backend, err := newWGBackend(ifaceName)
	if err != nil {
		return err
	}
	defer backend.Close()

	peers := enrolledPeers

	if *peerKeyFlag != "" {
		if *peerAddrFlag == "" {
			return errors.New(
				"peer-addr is required when peer-key is set",
			)
		}

		peerCfg, err := buildPeerConfig(
			*peerKeyFlag,
			*peerEndpointFlag,
			*peerAddrFlag,
			*peerAddr6Flag,
			*peerPSKFlag,
		)
		if err != nil {
			return err
		}

		peers = append(peers, peerCfg)
	}

	// Apply the full initial configuration — private key, listen port,
	// and the peer set — through the backend (ReplacePeers clears any
	// stale peers from a previous device).
	if err := backend.ConfigureDevice(wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        peers,
	}); err != nil {
		return err
	}

	fmt.Println("[agent] wireguard interface setup complete")
	fmt.Println("[agent] direct peer connectivity requires each peer to reach the configured endpoint over UDP")

	// Telemetry/reporting keeps the mesh converged and drives relay
	// fallback. It runs on both platforms: the backend abstracts kernel
	// WireGuard (Linux) and the embedded device (Windows), so config
	// sync and relay fallback now work on Windows too. Conntrack flow
	// telemetry stays Linux-only (newFlowDumper returns nil elsewhere).
	var reporterStop chan struct{}
	if authToken != "" {
		transport, err := parseRelayTransport(*relayTransportFlag)
		if err != nil {
			return err
		}

		reporter, err := newTelemetryReporter(
			backend,
			*serverFlag,
			authToken,
			*serverCAFlag,
			ifaceName,
			overlayAddr,
			overlayAddr6,
			networkPrefix,
			networkPrefix6,
			*reportIntervalFlag,
			transport,
		)
		if err != nil {
			slog.Error("telemetry init failed", "error", err)
		} else {
			reporterStop = make(chan struct{})
			go reporter.run(reporterStop)
			fmt.Printf("[agent] telemetry reporting enabled every %s\n", *reportIntervalFlag)
		}
	}

	// Block until terminated.
	waitForShutdown(stop)

	if reporterStop != nil {
		close(reporterStop)
	}

	return nil
}

func main() {
	if handled, err := handlePlatformCommand(os.Args); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
