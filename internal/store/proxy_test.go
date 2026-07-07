package store

import (
	"context"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

func TestProxyEventsStoredAndListed(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	key, _ := wgtypes.GeneratePrivateKey()
	peer, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "traefik", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	if err := st.ApplyReport(ctx, peer.Peer.ID, "192.0.2.10", &proto.ReportRequest{
		ProxyEvents: []proto.ProxyEvent{
			{At: "2026-07-07T11:00:00Z", Method: "GET", Host: "gitea.example.com", Path: "/x",
				Status: 200, DurationMS: 4, ReqBytes: 10, RespBytes: 2048, ClientIP: "100.78.0.4", Service: "gitea"},
			{At: "", Method: "POST", Host: "muse.example.com", Path: "/y", Status: 500, ClientIP: "100.78.0.5"},
		},
	}); err != nil {
		t.Fatalf("ApplyReport: %v", err)
	}

	rows, err := st.ListProxyEvents(ctx, 50)
	if err != nil {
		t.Fatalf("ListProxyEvents: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d proxy events, want 2", len(rows))
	}

	// Newest first (id DESC): the POST (inserted second) is newest, and its
	// empty timestamp is defaulted to the report time.
	if rows[0].Method != "POST" || rows[0].Status != 500 || rows[0].At == "" {
		t.Fatalf("row[0] = %+v, want POST 500 with a defaulted timestamp", rows[0])
	}
	if rows[1].Method != "GET" || rows[1].Host != "gitea.example.com" || rows[1].RespBytes != 2048 {
		t.Fatalf("row[1] = %+v, want the GET 200", rows[1])
	}
	if rows[0].PeerHostname != "traefik" {
		t.Fatalf("reporter = %q, want traefik", rows[0].PeerHostname)
	}
}
