package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"gowireguard/internal/proto"
)

func TestSignalWSReceivesSyncBroadcast(t *testing.T) {
	srv, ts := newTestServer(t)
	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	peer := enrollPeer(t, ts, setupKey, "node-a")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/signal"
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, http.Header{"Authorization": []string{"Bearer " + peer.AuthToken}})
	if err != nil {
		t.Fatalf("dial signal: %v", err)
	}
	defer conn.Close()

	msg := readSignalTestMessage(t, ctx, conn)
	if msg.Type != "hello" {
		t.Fatalf("first signal message type = %q, want hello", msg.Type)
	}

	srv.signalSync("test")

	msg = readSignalTestMessage(t, ctx, conn)
	if msg.Type != "sync-now" {
		t.Fatalf("broadcast signal message type = %q, want sync-now", msg.Type)
	}
	if !strings.Contains(string(msg.Payload), "test") {
		t.Fatalf("sync payload = %s, want reason test", msg.Payload)
	}
}

// TestPunchEpochBumpSignalsRemotePeer covers the coordination fast
// path: when one side's relayed report bumps the pair's punch epoch,
// the OTHER side is told to sync immediately instead of discovering the
// epoch up to a report interval later — hole punching lives and dies on
// both sides probing at the same time.
func TestPunchEpochBumpSignalsRemotePeer(t *testing.T) {
	srv, ts := newTestServer(t)
	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	self := enrollPeer(t, ts, setupKey, "self")
	remote, remoteKey := enrollPeerKey(t, ts, setupKey, "remote")

	// The remote must count as online (last_seen fresh) for the punch
	// decision, and must be connected to the signal hub to be reachable.
	reportAs(t, ts, remote.AuthToken)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/signal"
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, http.Header{"Authorization": []string{"Bearer " + remote.AuthToken}})
	if err != nil {
		t.Fatalf("dial signal: %v", err)
	}
	defer conn.Close()

	if msg := readSignalTestMessage(t, ctx, conn); msg.Type != "hello" {
		t.Fatalf("first signal message type = %q, want hello", msg.Type)
	}

	// Self reports the pair as relayed -> the server bumps the punch
	// epoch and must nudge the remote.
	reportPathState(t, ts, self.AuthToken, remoteKey.PublicKey().String(), "ws-relay")

	msg := readSignalTestMessage(t, ctx, conn)
	if msg.Type != "sync-now" {
		t.Fatalf("signal message type = %q, want sync-now", msg.Type)
	}
	if !strings.Contains(string(msg.Payload), "punch") {
		t.Fatalf("sync payload = %s, want reason punch", msg.Payload)
	}
}

func reportPathState(t *testing.T, ts *httptest.Server, authToken, peerKey, state string) {
	t.Helper()

	body, _ := json.Marshal(proto.ReportRequest{
		PathStates: []proto.PeerPathState{{PeerPublicKey: peerKey, State: state}},
	})

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/report", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /report: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("report status %d", resp.StatusCode)
	}
}

func readSignalTestMessage(t *testing.T, ctx context.Context, conn *websocket.Conn) signalMessage {
	t.Helper()

	deadline, ok := ctx.Deadline()
	if ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
	}

	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read signal message: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("signal message type = %v, want text", mt)
	}

	var msg signalMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("decode signal message: %v", err)
	}

	return msg
}
