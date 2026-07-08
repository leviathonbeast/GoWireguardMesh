package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
