//go:build windows

package main

import (
	"errors"
	"fmt"
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
	default:
		return serviceUsage()
	}
}

func serviceUsage() error {
	return errors.New(`usage:
  agent.exe service install [agent flags...]
  agent.exe service start
  agent.exe service stop
  agent.exe service remove

example:
  agent.exe service install --server https://mesh.example.com --setup-key <key> --listen-port 51820 --key-file C:\ProgramData\wgmesh-agent\wgkey.key`)
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

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop service %q: %w", windowsServiceName, err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("stop service %q: timed out", windowsServiceName)
		}
		time.Sleep(500 * time.Millisecond)

		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query service %q: %w", windowsServiceName, err)
		}
	}

	fmt.Printf("stopped %s\n", windowsServiceName)
	return nil
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
