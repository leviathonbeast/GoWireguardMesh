//go:build !linux

package main

import "gowireguard/internal/proto"

func applyOverlayACL(string, *proto.ACLPolicy) error { return nil }
