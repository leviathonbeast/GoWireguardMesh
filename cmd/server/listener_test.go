package main

import (
	"net"
	"testing"

	proxyproto "github.com/pires/go-proxyproto"
)

func TestProxyHeaderPolicy(t *testing.T) {
	trusted, err := parseTrustedProxies("172.18.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	policy := proxyHeaderPolicy(trusted)

	mk := func(ip string) proxyproto.ConnPolicyOptions {
		return proxyproto.ConnPolicyOptions{
			Upstream: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000},
		}
	}

	if p, _ := policy(mk("172.18.0.3")); p != proxyproto.USE {
		t.Fatalf("trusted proxy: got %v, want USE", p)
	}

	if p, _ := policy(mk("203.0.113.9")); p != proxyproto.IGNORE {
		t.Fatalf("direct client: got %v, want IGNORE", p)
	}
}

// TestProxyProtocolListenerRewritesRemoteAddr exercises the real
// accept path: a header from a trusted source must replace
// RemoteAddr, which is what rate limiting and the logs key on.
func TestProxyProtocolListenerRewritesRemoteAddr(t *testing.T) {
	trusted, err := parseTrustedProxies("127.0.0.0/8, ::1")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := buildListener("127.0.0.1:0", true, trusted)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- "accept: " + err.Error()
			return
		}
		defer conn.Close()

		// Reading triggers header parsing on the wrapped conn.
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			got <- "read: " + err.Error()
			return
		}

		got <- conn.RemoteAddr().String()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	header := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("92.40.214.58"), Port: 41000},
		&net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443})
	if _, err := header.WriteTo(conn); err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	if addr := <-got; addr != "92.40.214.58:41000" {
		t.Fatalf("RemoteAddr = %q, want 92.40.214.58:41000", addr)
	}
}
