package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	ifaceName  = "wg-int"
	listenPort = 51820
)

var (
	addrFlag         = flag.String("addr", "100.64.0.1/16", "overlay address (CIDR)")
	peerKeyFlag      = flag.String("peer-key", "", "peer public key (base64)")
	peerEndpointFlag = flag.String("peer-endpoint", "", "peer endpoint host:port (optional)")
	peerAddrFlag     = flag.String("peer-addr", "", "peer overlay address, e.g. 100.64.0.2/32")
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
	allowedCIDR string,
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

	keepalive := 25 * time.Second

	cfg := wgtypes.PeerConfig{
		PublicKey: publicKey,
		Endpoint:  udpAddr,
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

func run() error {
	flag.Parse()

	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}

	// Cleanup stale interface if present.
	if err := deleteInterface(ifaceName); err != nil {
		return err
	}

	privateKey, err := loadOrGenerateKey("wgkey.key")
	if err != nil {
		return err
	}

	fmt.Printf("Public Key: %s\n", privateKey.PublicKey())

	defer func() {
		if err := deleteInterface(ifaceName); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup error: %v\n", err)
		}
	}()

	if err := createInterface(ifaceName); err != nil {
		return err
	}

	if err := assignIPAddress(ifaceName, *addrFlag); err != nil {
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

	var peers []wgtypes.PeerConfig

	if *peerKeyFlag != "" {
		if *peerAddrFlag == "" {
			return errors.New("peer-addr is required when peer-key is set")
		}

		peerCfg, err := buildPeerConfig(
			*peerKeyFlag,
			*peerEndpointFlag,
			*peerAddrFlag,
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
