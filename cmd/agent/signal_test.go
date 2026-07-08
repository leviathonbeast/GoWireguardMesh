package main

import "testing"

func TestSignalWSURL(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   string
	}{
		{name: "http", server: "http://mesh.example", want: "ws://mesh.example/signal"},
		{name: "https", server: "https://mesh.example", want: "wss://mesh.example/signal"},
		{name: "base path", server: "https://mesh.example/api", want: "wss://mesh.example/api/signal"},
		{name: "trailing slash", server: "https://mesh.example/api/", want: "wss://mesh.example/api/signal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := signalWSURL(tt.server)
			if err != nil {
				t.Fatalf("signalWSURL() returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("signalWSURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
