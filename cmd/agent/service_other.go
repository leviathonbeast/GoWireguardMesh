//go:build !windows

package main

func handlePlatformCommand(args []string) (bool, error) {
	return false, nil
}
