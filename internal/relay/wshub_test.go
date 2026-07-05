package relay

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeConn is an in-memory FrameConn: frames written to it land on rx.
type fakeConn struct {
	rx     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeConn() *fakeConn {
	return &fakeConn{rx: make(chan []byte, 16), closed: make(chan struct{})}
}

func (f *fakeConn) ReadFrame() ([]byte, error) {
	select {
	case b := <-f.rx:
		return b, nil
	case <-f.closed:
		return nil, errors.New("closed")
	}
}

func (f *fakeConn) WriteFrame(b []byte) error {
	select {
	case f.rx <- b:
		return nil
	case <-f.closed:
		return errors.New("closed")
	}
}

func (f *fakeConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func TestWSHubForwardsBetweenMembers(t *testing.T) {
	h := NewWSHub()

	// A and B are the two ends the hub bridges; the "wire" conns are
	// what A and B write into / read out of.
	aWire, bWire := newFakeConn(), newFakeConn()

	go h.Serve("pair1", "keyA", aWire)
	go h.Serve("pair1", "keyB", bWire)

	// Let both join.
	time.Sleep(50 * time.Millisecond)

	// A sends a frame: it should arrive on B's wire.
	aWire.rx <- []byte("hello-from-A")

	select {
	case got := <-bWire.rx:
		if string(got) != "hello-from-A" {
			t.Fatalf("B received %q, want hello-from-A", got)
		}
	case <-time.After(time.Second):
		t.Fatal("frame from A never reached B")
	}
}

func TestWSHubDropsFrameWithNoPeer(t *testing.T) {
	h := NewWSHub()
	aWire := newFakeConn()

	go h.Serve("solo", "keyA", aWire)
	time.Sleep(20 * time.Millisecond)

	// No second member: this must not block or panic. Serve reads it
	// and drops it.
	aWire.rx <- []byte("into-the-void")
	time.Sleep(20 * time.Millisecond)
}

func TestWSHubRejectsThirdMember(t *testing.T) {
	h := NewWSHub()

	if _, err := h.join("p", "a", newFakeConn()); err != nil {
		t.Fatalf("first join: %v", err)
	}
	if _, err := h.join("p", "b", newFakeConn()); err != nil {
		t.Fatalf("second join: %v", err)
	}
	if _, err := h.join("p", "c", newFakeConn()); !errors.Is(err, errPairFull) {
		t.Fatalf("third join err = %v, want errPairFull", err)
	}
}

func TestWSHubRejoinReplacesConn(t *testing.T) {
	h := NewWSHub()
	first := newFakeConn()

	if _, err := h.join("p", "a", first); err != nil {
		t.Fatalf("join: %v", err)
	}

	// Same member reconnects: allowed, and the old conn is closed.
	if _, err := h.join("p", "a", newFakeConn()); err != nil {
		t.Fatalf("rejoin: %v", err)
	}

	select {
	case <-first.closed:
	default:
		t.Fatal("rejoin did not close the superseded connection")
	}
}
