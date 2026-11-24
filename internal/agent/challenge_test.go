package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/eddiexyang/graphnet/internal/control"
	"github.com/eddiexyang/graphnet/internal/controltransport"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/pki"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

type recordingUpdater struct {
	downloaded chan []byte
}

func (u *recordingUpdater) Status() *model.UpdateStatus {
	return &model.UpdateStatus{Managed: true, OS: "linux", Arch: "amd64"}
}

func (u *recordingUpdater) Start(req model.UpdateRequest, client *http.Client, server string) error {
	resp, err := client.Get(server + "/api/v1/agent/update/download/" + string(req.ID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	select {
	case u.downloaded <- body:
	default:
	}
	return nil
}

func (u *recordingUpdater) Poll(func() *http.Client, string) {}

type gatewayTestRuntime struct {
	applied chan model.Snapshot
}

func (r gatewayTestRuntime) Apply(_ context.Context, s model.Snapshot) error {
	select {
	case r.applied <- s:
	default:
	}
	return nil
}
func (gatewayTestRuntime) Report() []model.LinkStatus { return nil }
func (gatewayTestRuntime) LocalRouting() bool         { return true }

// TestHTTPSGatewayLearnsNothing runs enrollment, control synchronization and
// server-hosted binary update downloads through a TLS-terminating gateway that
// records every HTTP header, path and forwarded frame.
func TestHTTPSGatewayLearnsNothing(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	updateDir := filepath.Join(dir, "updates")
	if err := os.MkdirAll(updateDir, 0700); err != nil {
		t.Fatal(err)
	}

	binaryPayload := []byte("GRAPHNET-SECRET-BINARY-PAYLOAD-MARKER-9876543210")
	sum := sha256.Sum256(binaryPayload)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(updateDir, digest), binaryPayload, 0700); err != nil {
		t.Fatal(err)
	}
	asset := model.ReleaseAsset{
		Version: "v9.9.9",
		OS:      "linux",
		Arch:    "amd64",
		Name:    "graphnet-v9.9.9-linux-amd64",
		URL:     "https://github.com/eddiexyang/graphnet/releases/download/v9.9.9/graphnet-v9.9.9-linux-amd64",
		SHA256:  digest,
		Size:    int64(len(binaryPayload)),
	}
	if err := asset.Validate(); err != nil {
		t.Fatal(err)
	}

	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	fixture := testutil.Topology()
	secretNetworkName := "SecretOverlayNetworkMarker42"
	fixture.Networks[0].Name = secretNetworkName
	fixture.ClusterID = testutil.ID(99)
	fixture.ClusterCA = ca.PEM
	serverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Servers = []model.Server{{
		ID:        testutil.ID(90),
		Name:      "controller",
		PublicKey: serverPub,
		Endpoints: []model.ServerEndpoint{{ID: testutil.ID(91), Transport: "tcp", Source: model.Manual, URL: "tcp://127.0.0.1:1"}},
	}}
	current, _ := db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { *s = fixture; return nil }); err != nil {
		t.Fatal(err)
	}

	ctrl, err := control.New(db, control.Options{Password: "test-password-123", UpdateDirectory: updateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

	tlsConfig, err := ca.ServerTLS([]string{"127.0.0.1", fixture.Servers[0].TLSName()})
	if err != nil {
		t.Fatal(err)
	}
	ctrlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctrlServer := controltransport.NewServer(ctrlListener, ctrl, tlsConfig)
	go ctrlServer.Serve()
	defer func() {
		ctrlServer.Close()
		ctrlServer.Wait()
	}()

	// Mint a real enrollment token via the controller's direct admin HTTPS API.
	controllerRoots := x509.NewCertPool()
	controllerRoots.AppendCertsFromPEM(ca.PEM)
	jar, _ := cookiejar.New(nil)
	adminHTTP := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: controllerRoots, MinVersion: tls.VersionTLS13}}}
	defer adminHTTP.CloseIdleConnections()

	adminOrigin := "https://" + ctrlListener.Addr().String()
	loginResp, err := adminHTTP.Post(adminOrigin+"/api/v1/login", "application/json", strings.NewReader(`{"password":"test-password-123"}`))
	if err != nil || loginResp.StatusCode != 200 {
		t.Fatalf("admin login: %v %v", err, loginResp)
	}
	var loginData struct {
		CSRF string `json:"csrf_token"`
	}
	json.NewDecoder(loginResp.Body).Decode(&loginData)
	loginResp.Body.Close()

	tokReq, _ := http.NewRequest("POST", adminOrigin+"/api/v1/enrollment-tokens", strings.NewReader(`{}`))
	tokReq.Header.Set("Content-Type", "application/json")
	tokReq.Header.Set("X-CSRF-Token", loginData.CSRF)
	tokResp, err := adminHTTP.Do(tokReq)
	if err != nil || tokResp.StatusCode != 201 {
		t.Fatalf("create enrollment token: %v %v", err, tokResp)
	}
	var createdToken struct {
		Token string `json:"token"`
	}
	json.NewDecoder(tokResp.Body).Decode(&createdToken)
	tokResp.Body.Close()
	if createdToken.Token == "" {
		t.Fatal("empty enrollment token")
	}

	// Recording TLS-terminating gateway: terminates outer TLS with its own
	// certificate and forwards only plaintext WebSocket frames on WebSocketPath.
	var mu sync.Mutex
	var recorded bytes.Buffer
	record := func(data []byte) {
		mu.Lock()
		recorded.Write(data)
		mu.Unlock()
	}
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record([]byte(r.Method + " " + r.URL.RequestURI() + "\n"))
		for k, vals := range r.Header {
			for _, v := range vals {
				record([]byte(k + ": " + v + "\n"))
			}
		}
		if r.URL.Path != controltransport.WebSocketPath {
			http.Error(w, "gateway forwards only the tunnel path", http.StatusBadGateway)
			return
		}
		backendURL := "ws://" + ctrlListener.Addr().String() + controltransport.WebSocketPath
		up, resp, err := websocket.Dial(r.Context(), backendURL, &websocket.DialOptions{
			Subprotocols:    []string{controltransport.WebSocketProtocol},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer up.CloseNow()
		down, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:    []string{controltransport.WebSocketProtocol},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer down.CloseNow()
		up.SetReadLimit(1 << 20)
		down.SetReadLimit(1 << 20)
		errc := make(chan error, 2)
		pump := func(dst, src *websocket.Conn) {
			for {
				kind, payload, err := src.Read(r.Context())
				if err != nil {
					errc <- err
					return
				}
				record(payload)
				if err := dst.Write(r.Context(), kind, payload); err != nil {
					errc <- err
					return
				}
			}
		}
		go pump(up, down)
		go pump(down, up)
		<-errc
	}))
	defer gateway.Close()
	gatewayRoots := x509.NewCertPool()
	gatewayRoots.AddCert(gateway.Certificate())

	cache, err := NewMemoryCache(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	runtime := gatewayTestRuntime{applied: make(chan model.Snapshot, 4)}
	updater := &recordingUpdater{downloaded: make(chan []byte, 1)}

	client, err := NewClient(cache, runtime, Options{
		Updater:         updater,
		Server:          gateway.URL,
		ServerTransport: "https",
		Name:            "tunneled-gateway-agent",
		EnrollmentToken: createdToken.Token,
		Roots:           controllerRoots,
		GatewayRoots:    gatewayRoots,
		Version:         "v1.0.0",
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	go client.Run(ctx)

	// Wait for enrollment, then attach the enrolled agent to the network and
	// queue a server-hosted update request.
	var enrolledID model.ID
	for deadline := time.Now().Add(10 * time.Second); enrolledID == ""; time.Sleep(25 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("agent did not enroll through https gateway")
		}
		reg, _ := cache.Registration()
		if reg != nil {
			enrolledID = reg.AgentID
		}
	}

	state, _ := db.Read()
	if _, err := db.Update(state.Revision, func(s *model.State) error {
		s.Networks[0].Nodes[0].AgentID = enrolledID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	notifyController := func() {
		t.Helper()
		st, _ := db.Read()
		patchBody, _ := json.Marshal(map[string]any{"name": "tunneled-gateway-agent"})
		patchReq, _ := http.NewRequest("PATCH", adminOrigin+"/api/v1/agents/"+string(enrolledID), bytes.NewReader(patchBody))
		patchReq.Header.Set("Content-Type", "application/json")
		patchReq.Header.Set("X-CSRF-Token", loginData.CSRF)
		patchReq.Header.Set("If-Match", jsonNumber(st.Revision))
		resp, err := adminHTTP.Do(patchReq)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("patch agent to notify stream: %v %v", err, resp)
		}
		resp.Body.Close()
	}
	notifyController()

	gotSnapshot := false
	for !gotSnapshot {
		select {
		case snap := <-runtime.applied:
			if len(snap.Networks) > 0 && snap.Networks[0].Name == secretNetworkName {
				gotSnapshot = true
			}
		case <-ctx.Done():
			t.Fatal("agent did not receive network snapshot through https gateway")
		}
	}

	// Wait until the controller has received the Agent's report with Managed=true.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("controller did not receive managed update telemetry")
		}
		resp, err := adminHTTP.Get(adminOrigin + "/api/v1/telemetry")
		if err != nil {
			t.Fatal(err)
		}
		var agents []model.AgentStatus
		json.NewDecoder(resp.Body).Decode(&agents)
		resp.Body.Close()
		ready := false
		for _, a := range agents {
			if a.AgentID == enrolledID && a.Update != nil && a.Update.Managed {
				ready = true
			}
		}
		if ready {
			break
		}
	}

	state, _ = db.Read()
	updateReq := &model.UpdateRequest{
		ID:        model.NewID(),
		Source:    "server",
		Asset:     asset,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.Update(state.Revision, func(s *model.State) error {
		for i := range s.Agents {
			if s.Agents[i].ID == enrolledID {
				s.Agents[i].Update = updateReq
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	notifyController()

	select {
	case gotBinary := <-updater.downloaded:
		if !bytes.Equal(gotBinary, binaryPayload) {
			t.Fatalf("downloaded binary %q, want %q", gotBinary, binaryPayload)
		}
	case <-ctx.Done():
		t.Fatal("agent did not download update binary through https gateway")
	}

	mu.Lock()
	wire := append([]byte(nil), recorded.Bytes()...)
	mu.Unlock()
	if len(wire) == 0 {
		t.Fatal("gateway recorded nothing")
	}
	for name, secret := range map[string][]byte{
		"enrollment token": []byte(createdToken.Token),
		"snapshot marker":  []byte(secretNetworkName),
		"enrolled id":      []byte(enrolledID),
		"update binary":    binaryPayload,
	} {
		if bytes.Contains(wire, secret) {
			t.Fatalf("gateway recording leaked %s", name)
		}
	}
}

func jsonNumber(v uint64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
