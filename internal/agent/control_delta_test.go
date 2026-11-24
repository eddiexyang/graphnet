package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/eddiexyang/graphnet/internal/model"
)

func TestReceivedDeltasSurviveApplyCoalescing(t *testing.T) {
	cache, _, _ := registeredController(t)
	base, _, _ := cache.Snapshots()
	reg, _ := cache.Registration()
	base.Servers = reg.Directory.Clone()
	base.Servers.Revision = base.Revision
	next := base.Clone()
	next.Revision++
	next.Servers.Revision = next.Revision
	next.Endpoints[0].URL = "udp://192.0.2.50:24752"
	last := next.Clone()
	last.Revision++
	last.Servers.Revision = last.Revision
	last.Endpoints[0].URL = "udp://192.0.2.51:24752"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{model.DeltaSubprotocol}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for _, message := range []model.ControlMessage{
			{Type: "config", Snapshot: base},
			{Type: "config_delta", Delta: model.EndpointDeltaFrom(*base, next)},
			{Type: "config_delta", Delta: model.EndpointDeltaFrom(next, last)},
			{Type: "heartbeat"},
		} {
			if err := wsjson.Write(ctx, conn, message); err != nil {
				return
			}
		}
		<-ctx.Done()
	}))
	defer server.Close()
	conn, _, err := websocket.Dial(ctx, strings.Replace(server.URL, "http://", "ws://", 1), &websocket.DialOptions{Subprotocols: []string{model.DeltaSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	c := &Client{cache: cache}
	updates, acks := make(chan model.Snapshot, 1), make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- c.readControl(ctx, conn, base.AgentID, updates, acks) }()
	select {
	case <-acks:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	got := <-updates
	if got.Revision != last.Revision || got.Endpoints[0].URL != last.Endpoints[0].URL {
		t.Fatal("delta was based on applied state instead of received state")
	}
	reg, err = cache.Registration()
	if err != nil || reg.Directory.Revision != last.Revision {
		t.Fatal("delta lost the authenticated server directory revision")
	}
	cancel()
	<-done
}

func TestRenewalSendsSmallAcknowledgement(t *testing.T) {
	cache, ca, identity := registeredController(t)
	base, _, _ := cache.Snapshots()
	next := base.Clone()
	next.Revision++
	next.Endpoints[0].ExpiresAt = time.Now().UTC().Add(time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{model.DeltaSubprotocol}})
		if err != nil {
			result <- err
			return
		}
		defer conn.CloseNow()
		if err = wsjson.Write(ctx, conn, model.ControlMessage{Type: "config", Snapshot: base}); err != nil {
			result <- err
			return
		}
		// Initial report and final settling sample precede the idle cadence.
		for count := 0; count < 2; {
			var m model.ControlMessage
			if err = wsjson.Read(ctx, conn, &m); err != nil {
				result <- err
				return
			}
			if m.Type == "ack" {
				count++
			}
		}
		if err = wsjson.Write(ctx, conn, model.ControlMessage{Type: "config_delta", Delta: model.EndpointDeltaFrom(*base, next)}); err != nil {
			result <- err
			return
		}
		var m model.ControlMessage
		if err = wsjson.Read(ctx, conn, &m); err != nil {
			result <- err
			return
		}
		if m.Type != "ack_revision" || m.Ack == nil || m.Ack.AppliedRevision != next.Revision || m.Report != nil {
			result <- fmt.Errorf("renewal repeated full telemetry: %+v", m)
			return
		}
		result <- nil
		<-ctx.Done()
	}))
	var err error
	server.TLS, err = ca.ServerTLS([]string{identity.TLSName()})
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	c, err := NewClient(cache, controllerTestRuntime{}, Options{Server: server.URL, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.reconcile.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	updates, acks := make(chan model.Snapshot, 1), make(chan struct{}, 1)
	applyDone := make(chan struct{})
	go func() { defer close(applyDone); c.applyLoop(ctx, updates, acks) }()
	connectDone := make(chan error, 1)
	go func() { connectDone <- c.connect(ctx, base.AgentID, updates, acks) }()
	select {
	case err := <-result:
		if err != nil {
			t.Error(err)
		}
	case err := <-connectDone:
		t.Error(err)
		cancel()
		<-applyDone
		return
	case <-ctx.Done():
		t.Error(ctx.Err())
	}
	cancel()
	<-connectDone
	<-applyDone
}

type failingRuntime struct{ failRev uint64 }

func (f failingRuntime) Apply(_ context.Context, s model.Snapshot) error {
	if s.Revision == f.failRev {
		return errors.New("synthetic apply failure")
	}
	return nil
}
func (failingRuntime) Report() []model.LinkStatus { return nil }

func TestPersistentConfigErrorNeverSendsAckRevision(t *testing.T) {
	cache, ca, identity := registeredController(t)
	base, _, _ := cache.Snapshots()
	bad := base.Clone()
	bad.Revision++
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	ackRevSeen := make(chan model.ControlMessage, 1)
	fullErrAckSeen := make(chan struct{}, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{model.DeltaSubprotocol}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_ = wsjson.Write(ctx, conn, model.ControlMessage{Type: "config", Snapshot: base})
		_ = wsjson.Write(ctx, conn, model.ControlMessage{Type: "config", Snapshot: &bad})
		for {
			var m model.ControlMessage
			if err := wsjson.Read(ctx, conn, &m); err != nil {
				return
			}
			if m.Type == "ack_revision" {
				select {
				case ackRevSeen <- m:
				default:
				}
				return
			}
			if m.Type == "ack" && m.Report != nil && m.Report.ConfigError != "" {
				select {
				case fullErrAckSeen <- struct{}{}:
				default:
				}
			}
		}
	}))
	var err error
	server.TLS, err = ca.ServerTLS([]string{identity.TLSName()})
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()

	c, err := NewClient(cache, failingRuntime{failRev: bad.Revision}, Options{Server: server.URL, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	updates, acks := make(chan model.Snapshot, 1), make(chan struct{}, 1)
	applyDone := make(chan struct{})
	go func() { defer close(applyDone); c.applyLoop(ctx, updates, acks) }()
	connectDone := make(chan error, 1)
	go func() { connectDone <- c.connect(ctx, base.AgentID, updates, acks) }()

	// Wait until the initial ConfigError ack is sent, then trigger multiple forced/retry acks
	// while ConfigError remains non-empty and unchanged.
	select {
	case <-fullErrAckSeen:
	case <-ctx.Done():
		t.Fatal("never saw initial ConfigError ack")
	}
	for range 4 {
		acks <- struct{}{}
		time.Sleep(30 * time.Millisecond)
	}
	select {
	case badMsg := <-ackRevSeen:
		t.Fatalf("emitted ack_revision while ConfigError was non-empty: %+v", badMsg)
	default:
	}
	cancel()
	<-connectDone
	<-applyDone
}
