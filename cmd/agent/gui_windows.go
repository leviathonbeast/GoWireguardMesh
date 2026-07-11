//go:build windows && gui

// The desktop GUI for the Windows agent: a Fyne window (status, peers,
// settings, logs) plus a system-tray icon that reflects connection
// state. The agent loop runs in-process, so the GUI needs the same
// elevation the console agent does; it offers a "runas" relaunch when
// started unprivileged.
//
// Built only with -tags gui so the plain agent.exe stays pure-Go
// (Fyne needs cgo). See deploy/build.sh.
package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

//go:embed assets/tray-off.png
var trayOffPNG []byte

//go:embed assets/tray-connecting.png
var trayConnectingPNG []byte

//go:embed assets/tray-on.png
var trayOnPNG []byte

//go:embed assets/tray-error.png
var trayErrorPNG []byte

var (
	resTrayOff        = fyne.NewStaticResource("tray-off.png", trayOffPNG)
	resTrayConnecting = fyne.NewStaticResource("tray-connecting.png", trayConnectingPNG)
	resTrayOn         = fyne.NewStaticResource("tray-on.png", trayOnPNG)
	resTrayError      = fyne.NewStaticResource("tray-error.png", trayErrorPNG)
)

// guiLog receives a copy of all agent output for the Logs tab.
var guiLog = &logRing{}

// wantGUI: the explicit subcommand always works; a bare invocation
// (double-clicked agent-gui.exe) also opens the GUI. Console usage with
// flags or subcommands is untouched.
func wantGUI(args []string) bool {
	if len(args) > 1 {
		return strings.EqualFold(args[1], "gui")
	}

	return true
}

// singleInstanceMutex keeps a handle on the named mutex for the whole
// process lifetime; releaseSingleInstance frees it early so an elevated
// relaunch can grab it before this process exits.
var singleInstanceMutex windows.Handle

func acquireSingleInstance() error {
	name, err := windows.UTF16PtrFromString(`Local\wgmesh-agent-gui`)
	if err != nil {
		return err
	}

	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return errors.New("the wgmesh agent GUI is already running (check the system tray)")
		}
		return fmt.Errorf("create single-instance mutex: %w", err)
	}

	singleInstanceMutex = handle
	return nil
}

func releaseSingleInstance() {
	if singleInstanceMutex != 0 {
		_ = windows.CloseHandle(singleInstanceMutex)
		singleInstanceMutex = 0
	}
}

func processElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated re-runs this executable's GUI through UAC.
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}

	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString("gui")
	if err != nil {
		return err
	}

	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL)
}

// windowsServiceActive reports whether the wgmesh-agent Windows service
// is doing anything: it owns the same wg-int adapter, so the GUI and
// the service must not run an agent loop at the same time.
func windowsServiceActive() bool {
	s, err := openService()
	if err != nil {
		return false // not installed (or SCM unreachable): nothing to fight
	}
	defer s.Close()

	status, err := s.Query()

	return err == nil && status.State != svc.Stopped
}

// agentController owns the in-process agent loop lifecycle.
type agentController struct {
	mu   sync.Mutex
	stop chan struct{}
	done chan struct{}
}

func (c *agentController) running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.done == nil {
		return false
	}

	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// start launches the agent loop; false means one is already running.
func (c *agentController) start(cfg agentConfig) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.done != nil {
		select {
		case <-c.done:
		default:
			return false
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	c.stop, c.done = stop, done

	statusPub.update(func(s *agentStatus) {
		*s = agentStatus{State: stateStarting, Server: cfg.Server}
	})

	go func() {
		defer close(done)

		err := (&agentRunner{cfg: cfg}).run(stop)

		statusPub.update(func(s *agentStatus) {
			s.Peers = nil
			if err != nil {
				s.State = stateError
				s.Err = err.Error()
				return
			}
			s.State = stateStopped
			s.Err = ""
		})

		if err != nil {
			agentPrintf("[agent] stopped with error: %v\n", err)
		}
	}()

	return true
}

func (c *agentController) requestStop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stop == nil {
		return
	}

	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

// stopAndWait requests a stop and waits for the loop to unwind (the
// runner tears down the adapter, firewall rule, and reporter on exit).
func (c *agentController) stopAndWait(timeout time.Duration) {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()

	if done == nil {
		return
	}

	c.requestStop()

	select {
	case <-done:
	case <-time.After(timeout):
	}
}

type agentGUI struct {
	app fyne.App
	win fyne.Window
	ctl agentController

	stateIcon  *widget.Icon
	stateLabel *widget.Label
	errLabel   *widget.Label
	toggleBtn  *widget.Button

	infoServer  *widget.Label
	infoPubKey  *widget.Label
	infoOverlay *widget.Label
	infoPort    *widget.Label

	peers       []peerStatus
	peerList    *widget.List
	peerEmpty   *widget.Label
	peerSummary *widget.Label

	logText   *widget.Label
	logScroll *container.Scroll

	trayMenu       *fyne.Menu
	trayStatus     *fyne.MenuItem
	trayConnect    *fyne.MenuItem
	trayDisconnect *fyne.MenuItem
	trayDesk       desktop.App

	lastState   string
	lastTooltip string
}

func launchGUI() error {
	if err := acquireSingleInstance(); err != nil {
		return err
	}

	// Everything the agent prints or logs also lands in the Logs tab.
	// Set before any agent loop can run.
	logMirror = guiLog
	statusPub.enable()

	a := app.NewWithID("io.wgmesh.agent")
	a.SetIcon(resTrayOn)

	g := &agentGUI{app: a}
	g.win = a.NewWindow("wgmesh Agent")
	g.win.Resize(fyne.NewSize(820, 620))

	g.win.SetContent(container.NewBorder(
		g.buildHeader(), nil, nil, nil,
		container.NewAppTabs(
			container.NewTabItemWithIcon("Peers", theme.ComputerIcon(), g.buildPeersTab()),
			container.NewTabItemWithIcon("Settings", theme.SettingsIcon(), g.buildSettingsTab()),
			container.NewTabItemWithIcon("Logs", theme.DocumentIcon(), g.buildLogsTab()),
		),
	))

	// Closing the window keeps the agent running; the app lives in the
	// tray until Quit is chosen there.
	g.win.SetCloseIntercept(func() { g.win.Hide() })

	g.setupTray()
	go g.pollLoop()

	g.win.ShowAndRun()

	// Window loop ended (tray Quit): make sure the agent is torn down.
	g.ctl.stopAndWait(15 * time.Second)
	releaseSingleInstance()

	return nil
}

func (g *agentGUI) buildHeader() fyne.CanvasObject {
	g.stateIcon = widget.NewIcon(resTrayOff)
	g.stateLabel = widget.NewLabelWithStyle("Disconnected", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	g.toggleBtn = widget.NewButtonWithIcon("Connect", theme.MediaPlayIcon(), g.onToggle)
	g.toggleBtn.Importance = widget.HighImportance

	g.errLabel = widget.NewLabel("")
	g.errLabel.Wrapping = fyne.TextWrapWord
	g.errLabel.Hide()

	g.infoServer = widget.NewLabel("—")
	g.infoPubKey = widget.NewLabelWithStyle("—", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	g.infoOverlay = widget.NewLabelWithStyle("—", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	g.infoPort = widget.NewLabelWithStyle("—", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})

	copyKey := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		if key := strings.TrimSpace(g.infoPubKey.Text); key != "" && key != "—" {
			g.app.Clipboard().SetContent(key)
		}
	})

	info := container.New(layoutTwoCol(),
		widget.NewLabel("Server"), g.infoServer,
		widget.NewLabel("Public key"), container.NewHBox(g.infoPubKey, copyKey),
		widget.NewLabel("Overlay IP"), g.infoOverlay,
		widget.NewLabel("Listen port"), g.infoPort,
	)

	top := container.NewBorder(nil, nil,
		container.NewHBox(g.stateIcon, g.stateLabel), g.toggleBtn)

	return container.NewPadded(container.NewVBox(
		top,
		g.errLabel,
		widget.NewCard("", "", info),
	))
}

// layoutTwoCol is a simple label/value grid: two columns, natural row
// height.
func layoutTwoCol() fyne.Layout {
	return &twoColLayout{}
}

type twoColLayout struct{}

func (l *twoColLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var labelW, valueW, height float32
	for i := 0; i+1 < len(objects); i += 2 {
		ls, vs := objects[i].MinSize(), objects[i+1].MinSize()
		if ls.Width > labelW {
			labelW = ls.Width
		}
		if vs.Width > valueW {
			valueW = vs.Width
		}
		row := ls.Height
		if vs.Height > row {
			row = vs.Height
		}
		height += row
	}
	return fyne.NewSize(labelW+valueW+theme.Padding(), height)
}

func (l *twoColLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	var labelW float32
	for i := 0; i < len(objects); i += 2 {
		if w := objects[i].MinSize().Width; w > labelW {
			labelW = w
		}
	}

	y := float32(0)
	for i := 0; i+1 < len(objects); i += 2 {
		label, value := objects[i], objects[i+1]
		row := label.MinSize().Height
		if h := value.MinSize().Height; h > row {
			row = h
		}
		label.Resize(fyne.NewSize(labelW, row))
		label.Move(fyne.NewPos(0, y))
		value.Resize(fyne.NewSize(size.Width-labelW-theme.Padding(), row))
		value.Move(fyne.NewPos(labelW+theme.Padding(), y))
		y += row
	}
}

func (g *agentGUI) buildPeersTab() fyne.CanvasObject {
	g.peerEmpty = widget.NewLabel("No peers yet — connect to see the mesh.")

	g.peerSummary = widget.NewLabel("")
	g.peerSummary.Hide()

	g.peerList = widget.NewList(
		func() int { return len(g.peers) },
		func() fyne.CanvasObject {
			title := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			detail := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
			return container.NewVBox(title, detail)
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {
			if id < 0 || id >= len(g.peers) {
				return
			}
			p := g.peers[id]
			box := o.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(peerTitle(p))
			box.Objects[1].(*widget.Label).SetText(peerDetail(p))
		},
	)

	return container.NewBorder(
		g.peerSummary, nil, nil, nil,
		container.NewStack(g.peerList, container.NewCenter(g.peerEmpty)),
	)
}

// peerSummaryText is the one-line mesh digest above the peer list.
func peerSummaryText(peers []peerStatus) string {
	direct, relayed := 0, 0
	for _, p := range peers {
		switch p.PathState {
		case "direct":
			direct++
		case "ws-relay", "udp-relay":
			relayed++
		}
	}

	return fmt.Sprintf("%d peers · %d direct · %d relayed", len(peers), direct, relayed)
}

func peerTitle(p peerStatus) string {
	ips := strings.Join(p.AllowedIPs, ", ")
	if ips == "" {
		ips = "(no allowed IPs)"
	}

	return fmt.Sprintf("%s   ·   %s", ips, pathBadge(p.PathState))
}

func peerDetail(p peerStatus) string {
	key := p.PublicKey
	if len(key) > 12 {
		key = key[:12] + "…"
	}

	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = "-"
	}

	return fmt.Sprintf("%s  endpoint %s  handshake %s  rx %s  tx %s",
		key, endpoint, shortAgo(p.LastHandshake), humanBytes(p.RxBytes), humanBytes(p.TxBytes))
}

func pathBadge(state string) string {
	switch state {
	case "direct":
		return "DIRECT"
	case "ws-relay", "udp-relay":
		return "RELAY (" + strings.TrimSuffix(state, "-relay") + ")"
	case "probing-direct":
		return "PROBING"
	case "":
		return "?"
	default:
		return strings.ToUpper(state)
	}
}

func shortAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}

	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (g *agentGUI) buildLogsTab() fyne.CanvasObject {
	g.logText = widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	g.logText.Selectable = true
	g.logText.Wrapping = fyne.TextWrapBreak
	g.logScroll = container.NewVScroll(g.logText)

	copyBtn := widget.NewButtonWithIcon("Copy all", theme.ContentCopyIcon(), func() {
		text, _ := guiLog.snapshot()
		g.app.Clipboard().SetContent(text)
	})

	saveBtn := widget.NewButtonWithIcon("Save…", theme.DownloadIcon(), func() {
		text, _ := guiLog.snapshot()
		fd := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, g.win)
				return
			}
			if wc == nil {
				return // cancelled
			}
			defer wc.Close()
			if _, err := wc.Write([]byte(text)); err != nil {
				dialog.ShowError(fmt.Errorf("write log file: %w", err), g.win)
			}
		}, g.win)
		fd.SetFileName("wgmesh-agent-" + time.Now().Format("20060102-150405") + ".log")
		fd.Show()
	})

	clearBtn := widget.NewButtonWithIcon("Clear", theme.DeleteIcon(), func() {
		guiLog.clear()
	})

	actions := container.NewHBox(layout.NewSpacer(), copyBtn, saveBtn, clearBtn)

	return container.NewBorder(nil, container.NewPadded(actions), nil, nil, g.logScroll)
}

func (g *agentGUI) setupTray() {
	desk, ok := g.app.(desktop.App)
	if !ok {
		return
	}

	g.trayDesk = desk

	show := fyne.NewMenuItem("Open wgmesh Agent", func() {
		g.win.Show()
		g.win.RequestFocus()
	})

	g.trayStatus = fyne.NewMenuItem("Status: disconnected", nil)
	g.trayStatus.Disabled = true

	g.trayConnect = fyne.NewMenuItem("Connect", func() { g.connect() })
	g.trayDisconnect = fyne.NewMenuItem("Disconnect", func() { g.disconnect() })
	g.trayDisconnect.Disabled = true

	quit := fyne.NewMenuItem("Quit", func() {
		g.ctl.stopAndWait(15 * time.Second)
		g.app.Quit()
	})

	g.trayMenu = fyne.NewMenu("wgmesh Agent",
		show,
		fyne.NewMenuItemSeparator(),
		g.trayStatus,
		g.trayConnect,
		g.trayDisconnect,
		fyne.NewMenuItemSeparator(),
		quit,
	)

	desk.SetSystemTrayMenu(g.trayMenu)
	desk.SetSystemTrayIcon(resTrayOff)
}

func (g *agentGUI) onToggle() {
	if g.ctl.running() {
		g.disconnect()
		return
	}

	g.connect()
}

func (g *agentGUI) connect() {
	if !processElevated() {
		dialog.ShowConfirm("Administrator required",
			"Creating the WireGuard adapter needs an elevated process.\n\nRestart the GUI as administrator?",
			func(ok bool) {
				if !ok {
					return
				}
				releaseSingleInstance()
				if err := relaunchElevated(); err != nil {
					dialog.ShowError(fmt.Errorf("elevated relaunch failed: %w", err), g.win)
					return
				}
				g.app.Quit()
			}, g.win)
		return
	}

	if windowsServiceActive() {
		dialog.ShowError(errors.New("the wgmesh-agent Windows service is running and owns the WireGuard adapter.\n\nStop it first (agent.exe service stop) or keep using the service instead of the GUI."), g.win)
		return
	}

	settings := loadSettings(g.app.Preferences())
	if err := settings.validate(); err != nil {
		dialog.ShowError(fmt.Errorf("check Settings: %w", err), g.win)
		return
	}

	cfg := settings.agentConfig()
	if err := os.MkdirAll(filepath.Dir(cfg.KeyFile), 0700); err != nil {
		dialog.ShowError(fmt.Errorf("create key directory: %w", err), g.win)
		return
	}

	g.ctl.start(cfg)
}

func (g *agentGUI) disconnect() {
	g.ctl.requestStop()
}

// pollLoop drives all UI refresh from hub/log snapshots; versions keep
// idle ticks free of redraws. Runs for the process lifetime.
func (g *agentGUI) pollLoop() {
	// ^uint64(0) forces the first paint even though the hub is empty.
	lastStatus, lastLog := ^uint64(0), ^uint64(0)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if st, v := statusPub.snapshot(); v != lastStatus {
			lastStatus = v
			fyne.Do(func() { g.applyStatus(st) })
		}

		if text, v := guiLog.snapshot(); v != lastLog {
			lastLog = v
			fyne.Do(func() {
				g.logText.SetText(text)
				g.logScroll.ScrollToBottom()
			})
		}
	}
}

// applyStatus paints one status snapshot. Runs on the Fyne UI thread.
func (g *agentGUI) applyStatus(st agentStatus) {
	label, icon := stateLook(st.State)

	g.stateLabel.SetText(label)
	g.stateIcon.SetResource(icon)

	if st.State == stateError && st.Err != "" {
		g.errLabel.SetText(st.Err)
		g.errLabel.Show()
	} else {
		g.errLabel.Hide()
	}

	g.applyToggle(st.State)
	g.applyInfo(st)
	g.applyPeers(st.Peers)
	g.applyTray(st, label, icon)
	g.notifyTransition(st)

	g.lastState = st.State
}

func stateLook(state string) (string, fyne.Resource) {
	switch state {
	case stateStarting:
		return "Connecting…", resTrayConnecting
	case stateRunning:
		return "Connected", resTrayOn
	case stateStopping:
		return "Disconnecting…", resTrayConnecting
	case stateError:
		return "Error", resTrayError
	default:
		return "Disconnected", resTrayOff
	}
}

func (g *agentGUI) applyToggle(state string) {
	switch state {
	case stateStarting, stateRunning:
		g.toggleBtn.SetText("Disconnect")
		g.toggleBtn.SetIcon(theme.MediaStopIcon())
		g.toggleBtn.Enable()
	case stateStopping:
		g.toggleBtn.SetText("Disconnect")
		g.toggleBtn.SetIcon(theme.MediaStopIcon())
		g.toggleBtn.Disable()
	default:
		g.toggleBtn.SetText("Connect")
		g.toggleBtn.SetIcon(theme.MediaPlayIcon())
		g.toggleBtn.Enable()
	}
}

func (g *agentGUI) applyInfo(st agentStatus) {
	setOrDash := func(l *widget.Label, s string) {
		if s == "" {
			s = "—"
		}
		l.SetText(s)
	}

	setOrDash(g.infoServer, st.Server)
	setOrDash(g.infoPubKey, st.PublicKey)

	overlay := st.OverlayAddr
	if st.OverlayAddr6 != "" {
		if overlay != "" {
			overlay += ", "
		}
		overlay += st.OverlayAddr6
	}
	setOrDash(g.infoOverlay, overlay)

	port := ""
	if st.ListenPort > 0 {
		port = fmt.Sprintf("%d/udp", st.ListenPort)
	}
	setOrDash(g.infoPort, port)
}

func (g *agentGUI) applyPeers(peers []peerStatus) {
	g.peers = peers

	if len(peers) == 0 {
		g.peerEmpty.Show()
		g.peerSummary.Hide()
	} else {
		g.peerEmpty.Hide()
		g.peerSummary.SetText(peerSummaryText(peers))
		g.peerSummary.Show()
	}

	g.peerList.Refresh()
}

func (g *agentGUI) applyTray(st agentStatus, label string, icon fyne.Resource) {
	if g.trayDesk == nil {
		return
	}

	g.trayDesk.SetSystemTrayIcon(icon)

	g.trayStatus.Label = "Status: " + strings.ToLower(label)
	busy := st.State == stateStarting || st.State == stateRunning || st.State == stateStopping
	g.trayConnect.Disabled = busy
	g.trayDisconnect.Disabled = !busy || st.State == stateStopping
	g.trayMenu.Refresh()

	// Fyne has no tray-tooltip API, but it drives the tray through the
	// singleton fyne.io/systray package, so setting the tooltip there
	// reaches the same icon. Safe if the tray is not up yet (logged
	// no-op), and peer publishes retry it every few seconds anyway.
	if tip := trayTooltip(st); tip != g.lastTooltip {
		g.lastTooltip = tip
		systray.SetTooltip(tip)
	}
}

// trayTooltip is the hover summary. NOTIFYICONDATA truncates at 128
// UTF-16 units, so keep it tight and cut long errors.
func trayTooltip(st agentStatus) string {
	switch st.State {
	case stateStarting:
		return clipTooltip("wgmesh Agent — connecting to " + st.Server)
	case stateRunning:
		direct := 0
		for _, p := range st.Peers {
			if p.PathState == "direct" {
				direct++
			}
		}

		tip := "wgmesh Agent — connected"
		if st.OverlayAddr != "" {
			tip += "\n" + st.OverlayAddr
		}
		tip += fmt.Sprintf("\n%d peers (%d direct)", len(st.Peers), direct)

		return clipTooltip(tip)
	case stateStopping:
		return "wgmesh Agent — disconnecting"
	case stateError:
		return clipTooltip("wgmesh Agent — error: " + st.Err)
	default:
		return "wgmesh Agent — disconnected"
	}
}

func clipTooltip(s string) string {
	const max = 120 // UTF-16 budget is 127; stay clear of it

	runes := []rune(s)
	if len(runes) <= max {
		return s
	}

	return string(runes[:max-1]) + "…"
}

// notifyTransition sends desktop notifications on the edges that
// matter while the window is hidden in the tray.
func (g *agentGUI) notifyTransition(st agentStatus) {
	if st.State == g.lastState {
		return
	}

	switch st.State {
	case stateRunning:
		g.app.SendNotification(fyne.NewNotification("wgmesh Agent", "Connected to "+st.Server))
	case stateError:
		g.app.SendNotification(fyne.NewNotification("wgmesh Agent", "Agent stopped: "+st.Err))
	}
}
