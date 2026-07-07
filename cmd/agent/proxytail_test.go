package main

import "testing"

func TestProxyTailerIngestParsesTraefikJSON(t *testing.T) {
	tl := &proxyTailer{stop: make(chan struct{})}
	line := `{"StartUTC":"2026-07-07T11:00:00Z","RequestMethod":"GET","RequestHost":"gitea.example.com",` +
		`"RequestPath":"/api/v1","DownstreamStatus":200,"Duration":4200000,"RequestContentSize":10,` +
		`"DownstreamContentSize":2048,"ClientHost":"100.78.0.4","ServiceName":"gitea@docker"}`

	tl.ingest([]byte(line))

	evs := tl.drain(10)
	if len(evs) != 1 {
		t.Fatalf("drain returned %d events, want 1", len(evs))
	}

	e := evs[0]
	if e.Method != "GET" || e.Host != "gitea.example.com" || e.Path != "/api/v1" {
		t.Fatalf("parsed request wrong: %+v", e)
	}
	if e.Status != 200 || e.DurationMS != 4 || e.ReqBytes != 10 || e.RespBytes != 2048 {
		t.Fatalf("parsed metrics wrong: %+v", e) // 4200000ns -> 4ms
	}
	if e.ClientIP != "100.78.0.4" || e.Service != "gitea@docker" || e.At != "2026-07-07T11:00:00Z" {
		t.Fatalf("parsed meta wrong: %+v", e)
	}
}

func TestProxyTailerIgnoresNonAccessLines(t *testing.T) {
	tl := &proxyTailer{stop: make(chan struct{})}
	tl.ingest([]byte(`not json at all`))
	tl.ingest([]byte(`{"level":"info","msg":"Configuration loaded"}`)) // Traefik app log, not access

	if evs := tl.drain(10); len(evs) != 0 {
		t.Fatalf("drain returned %d events, want 0", len(evs))
	}
}

func TestProxyTailerDrainIsFIFO(t *testing.T) {
	tl := &proxyTailer{stop: make(chan struct{})}
	for range 5 {
		tl.ingest([]byte(`{"RequestMethod":"GET","RequestHost":"h","DownstreamStatus":200}`))
	}

	if got := tl.drain(3); len(got) != 3 {
		t.Fatalf("first drain = %d, want 3", len(got))
	}
	if got := tl.drain(10); len(got) != 2 {
		t.Fatalf("second drain = %d, want 2", len(got))
	}
	if got := tl.drain(10); len(got) != 0 {
		t.Fatalf("third drain = %d, want 0", len(got))
	}
}
