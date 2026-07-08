//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsServiceName        = "wgmesh-agent"
	windowsServiceDisplayName = "wgmesh Agent"
)

func handlePlatformCommand(args []string) (bool, error) {
	if len(args) > 1 && args[1] == "service" {
		return true, handleServiceCommand(args[2:])
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, err
	}
	if !isService {
		return false, nil
	}

	return true, svc.Run(windowsServiceName, &agentService{})
}

type agentService struct{}

func (s *agentService) Execute(args []string, changes <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runWithStop(stop)
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-changes:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				if err := <-done; err != nil {
					fmt.Fprintln(os.Stderr, err)
					return false, 1
				}
				return false, 0
			default:
				status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return false, 1
			}
			return false, 0
		}
	}
}

func handleServiceCommand(args []string) error {
	if len(args) == 0 {
		return serviceUsage()
	}

	switch args[0] {
	case "install":
		return installService(args[1:])
	case "remove", "uninstall":
		return removeService()
	case "start":
		return startService()
	case "stop":
		return stopService()
	case "restart":
		return restartService()
	case "status":
		return statusService()
	case "update":
		return updateServiceBinary()
	default:
		return serviceUsage()
	}
}

func serviceUsage() error {
	return errors.New(`usage:
  agent.exe service install [agent flags...]
  agent.exe service start
  agent.exe service stop
  agent.exe service restart
  agent.exe service status
  agent.exe service update
  agent.exe service remove

example:
  agent.exe service install --server https://mesh.example.com --setup-key <key> --listen-port 51820 --key-file C:\ProgramData\wgmesh-agent\wgkey.key

update flow:
  download a new agent.exe anywhere, then run from an elevated prompt:
  .\agent.exe service update`)
}

func installService(agentArgs []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(windowsServiceName); err == nil {
		existing.Close()
		return fmt.Errorf("service %q already exists", windowsServiceName)
	}

	svcConfig := mgr.Config{
		DisplayName: windowsServiceDisplayName,
		Description: "wgmesh WireGuard mesh node agent",
		StartType:   mgr.StartAutomatic,
	}

	s, err := m.CreateService(windowsServiceName, exe, svcConfig, agentArgs...)
	if err != nil {
		return fmt.Errorf("create service %q: %w", windowsServiceName, err)
	}
	defer s.Close()

	fmt.Printf("installed %s with args: %s\n", windowsServiceName, strings.Join(agentArgs, " "))
	return nil
}

func removeService() error {
	s, err := openService()
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service %q: %w", windowsServiceName, err)
	}

	fmt.Printf("removed %s\n", windowsServiceName)
	return nil
}

func startService() error {
	s, err := openService()
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %q: %w", windowsServiceName, err)
	}

	fmt.Printf("started %s\n", windowsServiceName)
	return nil
}

func stopService() error {
	s, err := openService()
	if err != nil {
		return err
	}
	defer s.Close()

	if _, err := stopManagedService(s); err != nil {
		return err
	}

	fmt.Printf("stopped %s\n", windowsServiceName)
	return nil
}

func restartService() error {
	s, err := openService()
	if err != nil {
		return err
	}
	defer s.Close()

	wasRunning, err := stopManagedService(s)
	if err != nil {
		return err
	}
	if wasRunning {
		fmt.Printf("stopped %s\n", windowsServiceName)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %q: %w", windowsServiceName, err)
	}

	fmt.Printf("started %s\n", windowsServiceName)
	return nil
}

func statusService() error {
	s, err := openService()
	if err != nil {
		return err
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service %q: %w", windowsServiceName, err)
	}
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("query service config %q: %w", windowsServiceName, err)
	}

	fmt.Printf("%s: %s\n", windowsServiceName, serviceStateName(status.State))
	fmt.Printf("binary: %s\n", cfg.BinaryPathName)
	return nil
}

func updateServiceBinary() error {
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	s, err := openService()
	if err != nil {
		return err
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("query service config %q: %w", windowsServiceName, err)
	}
	target, err := serviceExecutablePath(cfg.BinaryPathName)
	if err != nil {
		return err
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve installed service path: %w", err)
	}

	if strings.EqualFold(source, target) {
		return fmt.Errorf("current executable is already the installed service binary; download the new agent.exe to a different path, then run service update from there")
	}

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service %q: %w", windowsServiceName, err)
	}
	shouldRestart := status.State == svc.Running || status.State == svc.StartPending || status.State == svc.PausePending || status.State == svc.Paused

	if _, err := stopManagedService(s); err != nil {
		return err
	}

	if err := replaceFile(source, target); err != nil {
		return err
	}

	fmt.Printf("updated %s binary: %s\n", windowsServiceName, target)
	if shouldRestart {
		if err := s.Start(); err != nil {
			return fmt.Errorf("start service %q after update: %w", windowsServiceName, err)
		}
		fmt.Printf("started %s\n", windowsServiceName)
	}

	return nil
}

func stopManagedService(s *managedService) (bool, error) {
	status, err := s.Query()
	if err != nil {
		return false, fmt.Errorf("query service %q: %w", windowsServiceName, err)
	}
	if status.State == svc.Stopped {
		return false, nil
	}
	if status.State == svc.StopPending {
		return true, waitForServiceStopped(s, status)
	}

	status, err = s.Control(svc.Stop)
	if err != nil {
		return false, fmt.Errorf("stop service %q: %w", windowsServiceName, err)
	}

	return true, waitForServiceStopped(s, status)
}

func waitForServiceStopped(s *managedService, status svc.Status) error {
	deadline := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("stop service %q: timed out", windowsServiceName)
		}
		time.Sleep(500 * time.Millisecond)

		next, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service %q: %w", windowsServiceName, err)
		}
		status = next
	}

	return nil
}

func serviceExecutablePath(binaryPath string) (string, error) {
	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return "", fmt.Errorf("service %q has an empty binary path", windowsServiceName)
	}
	if strings.HasPrefix(binaryPath, `"`) {
		rest := strings.TrimPrefix(binaryPath, `"`)
		path, _, ok := strings.Cut(rest, `"`)
		if !ok || strings.TrimSpace(path) == "" {
			return "", fmt.Errorf("parse service binary path %q", binaryPath)
		}
		return path, nil
	}

	lower := strings.ToLower(binaryPath)
	if idx := strings.Index(lower, ".exe"); idx >= 0 {
		return binaryPath[:idx+len(".exe")], nil
	}

	fields := strings.Fields(binaryPath)
	if len(fields) == 0 {
		return "", fmt.Errorf("parse service binary path %q", binaryPath)
	}
	return fields[0], nil
}

func replaceFile(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("create service binary directory: %w", err)
	}

	tmp := target + ".new"
	backup := target + ".old"
	_ = os.Remove(tmp)

	if err := copyFile(source, tmp); err != nil {
		return err
	}
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmp)
		return fmt.Errorf("move existing service binary aside: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Rename(backup, target)
		return fmt.Errorf("install updated service binary: %w", err)
	}
	_ = os.Remove(backup)

	return nil
}

func copyFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open update source %q: %w", source, err)
	}
	defer in.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create update target %q: %w", target, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy update binary: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close update target %q: %w", target, err)
	}

	return nil
}

func serviceStateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", state)
	}
}

func openService() (*managedService, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect to service manager: %w", err)
	}

	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		m.Disconnect()
		return nil, fmt.Errorf("open service %q: %w", windowsServiceName, err)
	}

	return &managedService{Service: s, manager: m}, nil
}

type managedService struct {
	*mgr.Service
	manager *mgr.Mgr
}

func (s *managedService) Close() error {
	errSvc := s.Service.Close()
	errMgr := s.manager.Disconnect()
	if errSvc != nil {
		return errSvc
	}
	return errMgr
}
