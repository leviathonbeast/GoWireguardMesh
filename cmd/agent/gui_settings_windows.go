//go:build windows && gui

package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Preference keys. Stored via Fyne's per-user preferences for the app
// ID io.wgmesh.agent. Note the setup key is stored in plaintext there,
// same trust level as the service's SCM-stored arguments.
const (
	prefServer         = "server"
	prefSetupKey       = "setup-key"
	prefHostname       = "hostname"
	prefListenPort     = "listen-port"
	prefKeyFile        = "key-file"
	prefServerCA       = "server-ca"
	prefRelayTransport = "relay-transport"
	prefLogLevel       = "log-level"
	prefSTUNServer     = "stun-server"
	prefManageFirewall = "manage-firewall"
	prefDirectProbe    = "direct-probe"
)

// defaultGUIListenPort is pinned rather than auto-selected: a stable
// port keeps the host-firewall rule stable across restarts.
const defaultGUIListenPort = 51820

const defaultSTUNServer = "stun.l.google.com:19302"

func defaultKeyFile() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}

	return filepath.Join(base, "wgmesh-agent", "wgkey.key")
}

// guiSettings is everything the GUI lets you configure. It maps onto
// agentConfig; the enrollment-derived fields (overlay address et al.)
// come from the control plane, so the GUI is enrollment-mode only.
type guiSettings struct {
	Server         string
	SetupKey       string
	Hostname       string
	ListenPort     int
	KeyFile        string
	ServerCA       string
	RelayTransport string
	LogLevel       string
	STUNServer     string
	ManageFirewall bool
	DirectProbe    bool
}

func loadSettings(p fyne.Preferences) guiSettings {
	return guiSettings{
		Server:         strings.TrimSpace(p.String(prefServer)),
		SetupKey:       strings.TrimSpace(p.String(prefSetupKey)),
		Hostname:       strings.TrimSpace(p.String(prefHostname)),
		ListenPort:     p.IntWithFallback(prefListenPort, defaultGUIListenPort),
		KeyFile:        strings.TrimSpace(p.StringWithFallback(prefKeyFile, defaultKeyFile())),
		ServerCA:       strings.TrimSpace(p.String(prefServerCA)),
		RelayTransport: p.StringWithFallback(prefRelayTransport, "auto"),
		LogLevel:       p.StringWithFallback(prefLogLevel, "info"),
		STUNServer:     strings.TrimSpace(p.StringWithFallback(prefSTUNServer, defaultSTUNServer)),
		ManageFirewall: p.BoolWithFallback(prefManageFirewall, true),
		DirectProbe:    p.BoolWithFallback(prefDirectProbe, true),
	}
}

func (s guiSettings) save(p fyne.Preferences) {
	p.SetString(prefServer, s.Server)
	p.SetString(prefSetupKey, s.SetupKey)
	p.SetString(prefHostname, s.Hostname)
	p.SetInt(prefListenPort, s.ListenPort)
	p.SetString(prefKeyFile, s.KeyFile)
	p.SetString(prefServerCA, s.ServerCA)
	p.SetString(prefRelayTransport, s.RelayTransport)
	p.SetString(prefLogLevel, s.LogLevel)
	p.SetString(prefSTUNServer, s.STUNServer)
	p.SetBool(prefManageFirewall, s.ManageFirewall)
	p.SetBool(prefDirectProbe, s.DirectProbe)
}

// advancedCustomized reports whether any advanced field differs from
// its default. The settings tab keeps the advanced section collapsed
// for the common case, but never hides a value the operator changed.
func (s guiSettings) advancedCustomized() bool {
	return s.Hostname != "" ||
		s.ListenPort != defaultGUIListenPort ||
		s.KeyFile != defaultKeyFile() ||
		s.ServerCA != "" ||
		s.RelayTransport != "auto" ||
		s.LogLevel != "info" ||
		s.STUNServer != defaultSTUNServer ||
		!s.ManageFirewall ||
		!s.DirectProbe
}

func (s guiSettings) validate() error {
	if s.Server == "" {
		return errors.New("server URL is required")
	}

	u, err := url.Parse(s.Server)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("server URL %q must look like https://mesh.example.com", s.Server)
	}

	if s.SetupKey == "" {
		return errors.New("setup key is required (create one in the web UI under Setup keys)")
	}

	if s.ListenPort < 0 || s.ListenPort > 65535 {
		return fmt.Errorf("listen port %d out of range (use 0 for auto)", s.ListenPort)
	}

	if s.KeyFile == "" {
		return errors.New("key file path is required")
	}

	if s.ServerCA != "" {
		if _, err := os.Stat(s.ServerCA); err != nil {
			return fmt.Errorf("server CA file: %w", err)
		}
	}

	return nil
}

func (s guiSettings) agentConfig() agentConfig {
	return agentConfig{
		// Enrollment overrides the overlay address; this is only the
		// standalone-mode default, mirrored from the --addr flag.
		Addr:           "100.64.0.1/16",
		Server:         s.Server,
		SetupKey:       s.SetupKey,
		Hostname:       s.Hostname,
		ServerCA:       s.ServerCA,
		ReportInterval: 30 * time.Second,
		STUNServer:     s.STUNServer,
		RelayTransport: s.RelayTransport,
		DirectProbe:    s.DirectProbe,
		ManageFirewall: s.ManageFirewall,
		KeyFile:        s.KeyFile,
		LogLevel:       s.LogLevel,
		ListenPort:     s.ListenPort,
	}
}

func (g *agentGUI) buildSettingsTab() fyne.CanvasObject {
	prefs := g.app.Preferences()
	s := loadSettings(prefs)

	server := widget.NewEntry()
	server.SetPlaceHolder("https://mesh.example.com")
	server.SetText(s.Server)

	setupKey := widget.NewPasswordEntry()
	setupKey.SetPlaceHolder("setup key from the web UI")
	setupKey.SetText(s.SetupKey)

	hostname := widget.NewEntry()
	hostname.SetPlaceHolder("defaults to this computer's name")
	hostname.SetText(s.Hostname)

	listenPort := widget.NewEntry()
	listenPort.SetPlaceHolder(strconv.Itoa(defaultGUIListenPort))
	listenPort.SetText(strconv.Itoa(s.ListenPort))

	keyFile := widget.NewEntry()
	keyFile.SetPlaceHolder(defaultKeyFile())
	keyFile.SetText(s.KeyFile)

	serverCA := widget.NewEntry()
	serverCA.SetPlaceHolder("optional: PEM file to pin a self-signed server cert")
	serverCA.SetText(s.ServerCA)

	relay := widget.NewSelect([]string{"auto", "quic", "websocket", "udp"}, nil)
	relay.SetSelected(s.RelayTransport)

	logLevel := widget.NewSelect([]string{"debug", "info", "warn", "error"}, nil)
	logLevel.SetSelected(s.LogLevel)

	stun := widget.NewEntry()
	stun.SetPlaceHolder("empty disables public endpoint discovery")
	stun.SetText(s.STUNServer)

	manageFW := widget.NewCheck("open the WireGuard port on Windows Firewall (removed on disconnect)", nil)
	manageFW.SetChecked(s.ManageFirewall)

	directProbe := widget.NewCheck("probe for direct paths while relayed", nil)
	directProbe.SetChecked(s.DirectProbe)

	collect := func() (guiSettings, error) {
		port := defaultGUIListenPort
		if text := strings.TrimSpace(listenPort.Text); text != "" {
			n, err := strconv.Atoi(text)
			if err != nil {
				return guiSettings{}, fmt.Errorf("listen port %q is not a number", text)
			}
			port = n
		}

		out := guiSettings{
			Server:         strings.TrimSpace(server.Text),
			SetupKey:       strings.TrimSpace(setupKey.Text),
			Hostname:       strings.TrimSpace(hostname.Text),
			ListenPort:     port,
			KeyFile:        strings.TrimSpace(keyFile.Text),
			ServerCA:       strings.TrimSpace(serverCA.Text),
			RelayTransport: relay.Selected,
			LogLevel:       logLevel.Selected,
			STUNServer:     strings.TrimSpace(stun.Text),
			ManageFirewall: manageFW.Checked,
			DirectProbe:    directProbe.Checked,
		}

		return out, out.validate()
	}

	save := widget.NewButtonWithIcon("Save settings", theme.DocumentSaveIcon(), func() {
		out, err := collect()
		if err != nil {
			dialog.ShowError(err, g.win)
			return
		}

		out.save(prefs)

		note := "Settings saved."
		if g.ctl.running() {
			note = "Settings saved. They take effect on the next connect."
		}
		dialog.ShowInformation("Settings", note, g.win)
	})
	save.Importance = widget.HighImportance

	// The two fields everyone must fill stay in plain sight; everything
	// with a sensible default lives behind the Advanced disclosure.
	connection := widget.NewCard(
		"Connection",
		"Registers with the control plane using a setup key from the web UI, then stays connected until you disconnect or quit.",
		widget.NewForm(
			widget.NewFormItem("Server URL", server),
			widget.NewFormItem("Setup key", setupKey),
		),
	)

	advancedForm := widget.NewForm(
		widget.NewFormItem("Hostname", hostname),
		widget.NewFormItem("Listen port (UDP)", listenPort),
		widget.NewFormItem("Key file", keyFile),
		widget.NewFormItem("Server CA (pin)", serverCA),
		widget.NewFormItem("Relay transport", relay),
		widget.NewFormItem("Log level", logLevel),
		widget.NewFormItem("STUN server", stun),
		widget.NewFormItem("", manageFW),
		widget.NewFormItem("", directProbe),
	)

	resetAdvanced := widget.NewButtonWithIcon("Reset to defaults", theme.ViewRefreshIcon(), func() {
		hostname.SetText("")
		listenPort.SetText(strconv.Itoa(defaultGUIListenPort))
		keyFile.SetText(defaultKeyFile())
		serverCA.SetText("")
		relay.SetSelected("websocket")
		logLevel.SetSelected("info")
		stun.SetText(defaultSTUNServer)
		manageFW.SetChecked(true)
		directProbe.SetChecked(true)
	})

	advanced := widget.NewAccordion(widget.NewAccordionItem(
		"Advanced options",
		container.NewVBox(advancedForm, container.NewHBox(resetAdvanced)),
	))
	// Collapsed by default, but a customized field must never be hidden.
	if s.advancedCustomized() {
		advanced.Open(0)
	}

	body := container.NewVScroll(container.NewPadded(container.NewVBox(
		connection,
		advanced,
	)))

	saveBar := container.NewPadded(container.NewBorder(nil, nil, nil, save))

	return container.NewBorder(nil, saveBar, nil, nil, body)
}
