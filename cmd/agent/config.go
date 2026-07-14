package main

import "time"

type agentConfig struct {
	Addr              string
	Addr6             string
	PeerKey           string
	PeerEndpoint      string
	PeerAddr          string
	PeerAddr6         string
	PeerPSK           string
	Server            string
	SetupKey          string
	Hostname          string
	ServerCA          string
	ReportInterval    time.Duration
	STUNServer        string
	PortMapping       bool
	RelayTransport    string
	DirectProbe       bool
	GatewayNATCIDRs   string
	AdvertiseEndpoint string
	DNSMode           string
	DNSFallback       bool
	ManageFirewall    bool
	NoIPv6            bool
	KeyFile           string
	LogLevel          string
	TraefikAccessLog  string
	ListenPort        int
}

func agentConfigFromFlags() agentConfig {
	return agentConfig{
		Addr:              *addrFlag,
		Addr6:             *addr6Flag,
		PeerKey:           *peerKeyFlag,
		PeerEndpoint:      *peerEndpointFlag,
		PeerAddr:          *peerAddrFlag,
		PeerAddr6:         *peerAddr6Flag,
		PeerPSK:           *peerPSKFlag,
		Server:            *serverFlag,
		SetupKey:          *setupKeyFlag,
		Hostname:          *hostnameFlag,
		ServerCA:          *serverCAFlag,
		ReportInterval:    *reportIntervalFlag,
		STUNServer:        *stunServerFlag,
		PortMapping:       *portMappingFlag,
		RelayTransport:    *relayTransportFlag,
		DirectProbe:       *directProbeFlag,
		GatewayNATCIDRs:   *gatewayNATCIDRsFlag,
		AdvertiseEndpoint: *advertiseEndpFlag,
		DNSMode:           *dnsModeFlag,
		DNSFallback:       *dnsFallbackFlag,
		ManageFirewall:    *manageFirewallFlag,
		NoIPv6:            *noIPv6Flag,
		KeyFile:           *keyFileFlag,
		LogLevel:          *logLevelFlag,
		TraefikAccessLog:  *traefikAccessLogFlag,
		ListenPort:        *listenPortFlag,
	}
}
