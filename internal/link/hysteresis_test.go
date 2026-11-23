package link

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
)

type selectionTestChannel struct {
	Channel
	id      string
	created time.Time
}

func (c selectionTestChannel) ID() string           { return c.id }
func (c selectionTestChannel) Created() time.Time   { return c.created }
func (c selectionTestChannel) RemoteAddr() net.Addr { return &net.UDPAddr{} }

func TestBusyPathSelection(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		rtt, currentRTT                time.Duration
		age, sinceSwitch               time.Duration
		rx, tx                         uint64
		failed, preferred, replacement bool
		want                           string
	}{
		// A healthy path is never left for a lower RTT, busy or idle.
		{name: "busy small improvement", rtt: 91 * time.Millisecond, tx: 1, want: "current"},
		{name: "receive only", rtt: 91 * time.Millisecond, rx: 1, want: "current"},
		{name: "idle", rtt: 99 * time.Millisecond, age: time.Minute, want: "current"},
		{name: "200 ms against 80 ms", currentRTT: 200 * time.Millisecond, rtt: 80 * time.Millisecond, tx: 1, want: "current"},
		{name: "fast path jitter", currentRTT: 5 * time.Millisecond, rtt: 4 * time.Millisecond, want: "current"},
		{name: "just switched and failed", rtt: 110 * time.Millisecond, sinceSwitch: time.Second, failed: true, want: "candidate"},
		{name: "failed active", rtt: 110 * time.Millisecond, tx: 1, failed: true, want: "candidate"},
		{name: "explicit preference", rtt: 110 * time.Millisecond, tx: 1, preferred: true, want: "candidate"},
		{name: "session replacement", rtt: 110 * time.Millisecond, tx: 1, replacement: true, want: "candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			makeLink := func(id string, rtt time.Duration) *Link {
				return &Link{channel: selectionTestChannel{id: id, created: now}, ctx: context.Background(), options: (Options{}).defaults(), info: Info{CandidateID: id}, lastPong: now, rtt: rtt, control: make(chan []byte, 8)}
			}
			if tc.currentRTT == 0 {
				tc.currentRTT = 100 * time.Millisecond
			}
			if tc.sinceSwitch == 0 {
				tc.sinceSwitch = time.Hour
			}
			current, candidate := makeLink("current", tc.currentRTT), makeLink("candidate", tc.rtt)
			current.rx.Store(tc.rx)
			current.tx.Store(tc.tx)
			current.lastTraffic = now.Add(-tc.age)
			if tc.failed {
				current.lastPong = time.Time{}
			}
			e := NewCoordinatedEdge(model.ID("a"), model.ID("b"), "")
			e.Add(current)
			e.Add(candidate)
			e.activateLocked(current, now.Add(-tc.sinceSwitch))
			e.selection.target = "current"
			e.selection.confirmed = true
			if tc.preferred {
				e.SetPreferred("candidate")
			}
			if tc.replacement {
				e.Replace("current", "candidate")
			}
			e.advanceLocked(now)
			if e.selection.target != tc.want {
				t.Fatalf("selected %s, want %s", e.selection.target, tc.want)
			}
		})
	}
}

func TestSelectionActivitySampling(t *testing.T) {
	now := time.Now()
	l := &Link{}
	if l.recentlyActive(now) {
		t.Fatal("idle link treated as busy")
	}
	l.rx.Add(1)
	if !l.recentlyActive(now) {
		t.Fatal("incoming data not detected")
	}
	if l.recentlyActive(now.Add(5 * time.Second)) {
		t.Fatal("activity window did not expire")
	}
	l.tx.Add(1)
	if !l.recentlyActive(now.Add(6 * time.Second)) {
		t.Fatal("outgoing data not detected")
	}
}
