package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"gowireguard/internal/proto"
)

const (
	proxyTailPoll     = 2 * time.Second
	proxyTailMaxQueue = 2000     // bounded buffer; oldest dropped past this
	proxyDrainPerTick = 256      // max events shipped per report
	proxyLineMax      = 64 << 10 // ignore absurdly long log lines
)

// traefikAccessLine is the subset of Traefik's JSON access-log format the
// mesh surfaces. Traefik must be configured to write a JSON access log.
type traefikAccessLine struct {
	StartUTC              string `json:"StartUTC"`
	RequestMethod         string `json:"RequestMethod"`
	RequestHost           string `json:"RequestHost"`
	RequestPath           string `json:"RequestPath"`
	DownstreamStatus      int    `json:"DownstreamStatus"`
	Duration              int64  `json:"Duration"` // nanoseconds
	DownstreamContentSize int64  `json:"DownstreamContentSize"`
	RequestContentSize    int64  `json:"RequestContentSize"`
	ClientHost            string `json:"ClientHost"`
	ServiceName           string `json:"ServiceName"`
}

// proxyTailer follows a reverse-proxy JSON access log, parsing new lines
// into ProxyEvents that the reporter drains and ships. It reopens the
// file each poll, so log rotation is handled without inotify.
type proxyTailer struct {
	path string

	mu    sync.Mutex
	queue []proto.ProxyEvent

	stop chan struct{}
	once sync.Once
}

func newProxyTailer(path string) *proxyTailer {
	t := &proxyTailer{path: path, stop: make(chan struct{})}
	go t.run()

	return t
}

func (t *proxyTailer) run() {
	ticker := time.NewTicker(proxyTailPoll)
	defer ticker.Stop()

	var offset int64 = -1 // -1: not yet positioned (start at end)

	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
		}

		fi, err := os.Stat(t.path)
		if err != nil {
			offset = -1 // gone (rotation); re-seek to end when it returns
			continue
		}

		size := fi.Size()
		switch {
		case offset < 0:
			offset = size // only ingest requests logged after we start
			continue
		case size < offset:
			offset = 0 // truncated/rotated in place
		case size == offset:
			continue // nothing new
		}

		offset = t.readNew(offset, size)
	}
}

// readNew reads bytes [offset,size), ingests complete lines, and returns
// the new offset (advanced only past complete lines so a partial trailing
// line is re-read once finished).
func (t *proxyTailer) readNew(offset, size int64) int64 {
	f, err := os.Open(t.path)
	if err != nil {
		return offset
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}

	data := make([]byte, size-offset)
	n, _ := io.ReadFull(f, data)
	data = data[:n]

	lastNL := bytes.LastIndexByte(data, '\n')
	if lastNL < 0 {
		return offset // no complete line yet
	}

	for _, line := range bytes.Split(data[:lastNL], []byte{'\n'}) {
		if len(line) > 0 {
			t.ingest(line)
		}
	}

	return offset + int64(lastNL) + 1
}

func (t *proxyTailer) ingest(line []byte) {
	if len(line) > proxyLineMax {
		return
	}

	var a traefikAccessLine
	if err := json.Unmarshal(line, &a); err != nil {
		return // not a JSON access-log line
	}
	if a.RequestMethod == "" && a.RequestHost == "" {
		return // not a recognizable access entry
	}

	ev := proto.ProxyEvent{
		At:         a.StartUTC,
		Method:     a.RequestMethod,
		Host:       a.RequestHost,
		Path:       a.RequestPath,
		Status:     a.DownstreamStatus,
		DurationMS: a.Duration / int64(time.Millisecond),
		ReqBytes:   a.RequestContentSize,
		RespBytes:  a.DownstreamContentSize,
		ClientIP:   a.ClientHost,
		Service:    a.ServiceName,
	}

	t.mu.Lock()
	if len(t.queue) >= proxyTailMaxQueue {
		t.queue = t.queue[len(t.queue)-proxyTailMaxQueue+1:]
	}
	t.queue = append(t.queue, ev)
	t.mu.Unlock()
}

// drain removes and returns up to max buffered events (FIFO).
func (t *proxyTailer) drain(max int) []proto.ProxyEvent {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.queue) == 0 {
		return nil
	}
	if max > len(t.queue) {
		max = len(t.queue)
	}

	out := make([]proto.ProxyEvent, max)
	copy(out, t.queue)
	t.queue = append(t.queue[:0], t.queue[max:]...)

	return out
}

func (t *proxyTailer) Close() {
	t.once.Do(func() { close(t.stop) })
}
