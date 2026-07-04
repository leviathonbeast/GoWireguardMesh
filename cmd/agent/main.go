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
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

const (
	ifaceName  = "wg-int"
	listenPort = 51820
)

var (
	addrFlag           = flag.String("addr", "100.64.0.1/16", "overlay address (CIDR)")
	peerKeyFlag        = flag.String("peer-key", "", "peer public key (base64)")
	peerEndpointFlag   = flag.String("peer-endpoint", "", "peer endpoint host:port (optional)")
	peerAddrFlag       = flag.String("peer-addr", "", "peer overlay address, e.g. 100.64.0.2/32")
	peerPSKFlag        = flag.String("peer-psk", "", "preshared key (base64, optional)")
	serverFlag         = flag.String("server", "", "control plane URL (e.g. https://host:8080); enables enrollment mode")
	setupKeyFlag       = flag.String("setup-key", "", "setup key for enrollment (required with --server)")
	serverCAFlag       = flag.String("server-ca", "", "PEM certificate to trust for the control plane (pin its self-signed cert.pem)")
	reportIntervalFlag = flag.Duration("report-interval", 30*time.Second, "telemetry reporting interval")
	keyFileFlag        = flag.String("key-file", "wgkey.key", "path to private key file")
)

func generatePrivateKey() (wgtypes.Key, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate private key: %w", err)
	}

	return privateKey, nil
}

func createInterface(name string) error {
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create interface %q: %w", name, err)
	}

	fmt.Printf("Created interface %s\n", name)

	return nil
}

func assignIPAddress(ifaceName, cidr string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("assign address %q: %w", cidr, err)
	}

	fmt.Printf("Assigned %s to %s\n", cidr, ifaceName)

	return nil
}

func bringInterfaceUp(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring interface up: %w", err)
	}

	fmt.Printf("Interface %s is UP\n", ifaceName)

	return nil
}

func deleteInterface(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}

		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete interface %q: %w", ifaceName, err)
	}

	fmt.Printf("Deleted interface %s\n", ifaceName)

	return nil
}

func configureWireGuard(
	client *wgctrl.Client,
	iface string,
	privateKey wgtypes.Key,
	listenPort int,
	peers []wgtypes.PeerConfig,
) error {
	cfg := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        peers,
	}

	if err := client.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("configure device %q: %w", iface, err)
	}

	fmt.Println("Configured WireGuard device")

	return nil
}

func printDeviceState(client *wgctrl.Client, iface string) error {
	device, err := client.Device(iface)
	if err != nil {
		return fmt.Errorf("read device %q: %w", iface, err)
	}

	fmt.Println("\n===== WireGuard Device =====")
	fmt.Printf("Name        : %s\n", device.Name)
	fmt.Printf("Public Key  : %s\n", device.PublicKey)
	fmt.Printf("Listen Port : %d\n", device.ListenPort)
	fmt.Printf("Peers       : %d\n", len(device.Peers))

	return nil
}

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)

	signal.Notify(
		sigCh,
		os.Interrupt,
		syscall.SIGTERM,
	)

	fmt.Println("\nWaiting for shutdown signal (Ctrl+C)...")

	sig := <-sigCh

	fmt.Printf("\nReceived signal: %s\n", sig)
}

func buildPeerConfig(
	pubkey,
	endpoint,
	allowedCIDR,
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
		PublicKey:    publicKey,
		Endpoint:     udpAddr,
		PresharedKey: psk,
		AllowedIPs: []net.IPNet{
			*allowedNet,
		},
		PersistentKeepaliveInterval: &keepalive,
	}

	return cfg, nil
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
func enroll(serverURL, setupKey, serverCA string, publicKey wgtypes.Key, hostname string, listenPort int) (*proto.EnrollResponse, error) {
	reqBody, err := json.Marshal(proto.EnrollRequest{
		SetupKey:   setupKey,
		PublicKey:  publicKey.String(),
		Hostname:   hostname,
		ListenPort: listenPort,
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

	if p.Endpoint != nil {
		udpAddr, err = net.ResolveUDPAddr("udp", *p.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("resolve endpoint %q: %w", *p.Endpoint, err)
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

func run() error {
	flag.Parse()

	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}

	// Cleanup stale interface if present.
	if err := deleteInterface(ifaceName); err != nil {
		return err
	}

	privateKey, err := loadOrGenerateKey(*keyFileFlag)
	if err != nil {
		return err
	}

	fmt.Printf("Public Key: %s\n", privateKey.PublicKey())

	// Enrollment mode: the control plane dictates our overlay address
	// and peer list; the manual --peer-* flags are the standalone path.
	overlayAddr := *addrFlag

	var (
		enrolledPeers []wgtypes.PeerConfig
		authToken     string
		meshNetwork   netip.Prefix
	)

	if *serverFlag != "" {
		if *setupKeyFlag == "" {
			return errors.New("--setup-key is required with --server")
		}

		hostname, _ := os.Hostname()

		resp, err := enroll(*serverFlag, *setupKeyFlag, *serverCAFlag, privateKey.PublicKey(), hostname, listenPort)
		if err != nil {
			return err
		}

		authToken = resp.AuthToken

		meshNetwork, err = netip.ParsePrefix(resp.NetworkCIDR)
		if err != nil {
			return fmt.Errorf("parse network CIDR %q from server: %w", resp.NetworkCIDR, err)
		}

		overlayAddr = fmt.Sprintf("%s/%d", resp.AssignedIP, meshNetwork.Bits())

		for _, p := range resp.Peers {
			cfg, err := peerConfigFromProto(p)
			if err != nil {
				return err
			}

			enrolledPeers = append(enrolledPeers, cfg)
		}

		fmt.Printf("Enrolled as peer %d, assigned %s, %d peer(s) in mesh\n",
			resp.PeerID, overlayAddr, len(resp.Peers))
	}

	defer func() {
		if err := deleteInterface(ifaceName); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup error: %v\n", err)
		}
	}()

	if err := createInterface(ifaceName); err != nil {
		return err
	}

	if err := assignIPAddress(ifaceName, overlayAddr); err != nil {
		return err
	}

	if err := bringInterfaceUp(ifaceName); err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("create wgctrl client: %w", err)
	}
	defer client.Close()

	peers := enrolledPeers

	if *peerKeyFlag != "" {
		if *peerAddrFlag == "" {
			return errors.New("peer-addr is required when peer-key is set")
		}

		peerCfg, err := buildPeerConfig(
			*peerKeyFlag,
			*peerEndpointFlag,
			*peerAddrFlag,
			*peerPSKFlag,
		)
		if err != nil {
			return err
		}

		peers = append(peers, peerCfg)
	}

	if err := configureWireGuard(
		client,
		ifaceName,
		privateKey,
		listenPort,
		peers,
	); err != nil {
		return err
	}

	if err := printDeviceState(client, ifaceName); err != nil {
		return err
	}

	fmt.Println("\nWireGuard interface setup complete")

	// Telemetry runs only in enrollment mode: without a control plane
	// there is nowhere to report.
	if authToken != "" {
		reporter, err := newTelemetryReporter(
			client,
			*serverFlag,
			authToken,
			*serverCAFlag,
			ifaceName,
			meshNetwork,
			*reportIntervalFlag,
		)
		if err != nil {
			return err
		}

		stop := make(chan struct{})
		done := make(chan struct{})

		go func() {
			defer close(done)
			reporter.run(stop)
		}()

		defer func() {
			close(stop)
			<-done
		}()

		fmt.Printf("Telemetry reporting every %s\n", *reportIntervalFlag)
	}

	// Block until terminated.
	waitForShutdown()

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
