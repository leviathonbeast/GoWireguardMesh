package main

import "time"

type agentConfig struct {
	Addr             string
	Addr6            string
	PeerKey          string
	PeerEndpoint     string
	PeerAddr         string
	PeerAddr6        string
	PeerPSK          string
	Server           string
	SetupKey         string
	Hostname         string
	ServerCA         string
	ReportInterval   time.Duration
	STUNServer       string
	RelayTransport   string
	DirectProbe      bool
	ManageFirewall   bool
	KeyFile          string
	LogLevel         string
	TraefikAccessLog string
	ListenPort       int
}

func agentConfigFromFlags() agentConfig {
	return agentConfig{
		Addr:             *addrFlag,
		Addr6:            *addr6Flag,
		PeerKey:          *peerKeyFlag,
		PeerEndpoint:     *peerEndpointFlag,
		PeerAddr:         *peerAddrFlag,
		PeerAddr6:        *peerAddr6Flag,
		PeerPSK:          *peerPSKFlag,
		Server:           *serverFlag,
		SetupKey:         *setupKeyFlag,
		Hostname:         *hostnameFlag,
		ServerCA:         *serverCAFlag,
		ReportInterval:   *reportIntervalFlag,
		STUNServer:       *stunServerFlag,
		RelayTransport:   *relayTransportFlag,
		DirectProbe:      *directProbeFlag,
		ManageFirewall:   *manageFirewallFlag,
		KeyFile:          *keyFileFlag,
		LogLevel:         *logLevelFlag,
		TraefikAccessLog: *traefikAccessLogFlag,
		ListenPort:       *listenPortFlag,
	}
}
