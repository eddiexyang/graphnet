package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/agent"
	"github.com/eddiexyang/graphnet/internal/control"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/pki"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/tunnel"
	updater "github.com/eddiexyang/graphnet/internal/update"
)

type noopTUN struct {
	cfg    tunnel.Config
	closed chan struct{}
	once   sync.Once
}

func (d *noopTUN) Read([]byte) (int, error) {
	<-d.closed
	return 0, io.EOF
}
func (d *noopTUN) Write(b []byte) (int, error) { return len(b), nil }
func (d *noopTUN) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}
func (d *noopTUN) Name() string                 { return d.cfg.Name }
func (d *noopTUN) Configuration() tunnel.Config { return d.cfg }

func installTestDataPlaneHook(t *testing.T) {
	t.Helper()
	prev := testAgentDataPlane
	testAgentDataPlane = func(opts *agent.DataPlaneOptions) {
		opts.Embedded = true
		opts.BindHost = "127.0.0.1"
		opts.TunnelFactory = func(cfg tunnel.Config) (tunnel.Device, error) {
			if cfg.Name == "" {
				cfg.Name = "gntest0"
			}
			return &noopTUN{cfg: cfg, closed: make(chan struct{})}, nil
		}
	}
	t.Cleanup(func() { testAgentDataPlane = prev })
}

func startTestController(t *testing.T) (*store.Store, *control.Server, *pki.Authority, *httptest.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	updateDir := filepath.Join(dir, "updates")
	db, err := store.Open(filepath.Join(dir, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	apiToken := "0123456789abcdef0123456789abcdef"
	srv, err := control.New(db, control.Options{
		Password:        "strong-admin-password-123",
		APIToken:        apiToken,
		UpdateDirectory: updateDir,
		Version:         "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	state, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	var serverNode model.Server
	if len(state.Servers) == 0 {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		serverNode = model.Server{ID: model.NewID(), Name: "ctrl", PublicKey: pub}
	} else {
		serverNode = state.Servers[0]
	}
	listener := httptest.NewUnstartedServer(srv)
	listener.TLS, err = ca.ServerTLS([]string{"127.0.0.1", "localhost", serverNode.TLSName()})
	if err != nil {
		t.Fatal(err)
	}
	listener.StartTLS()
	t.Cleanup(listener.Close)

	serverNode.Endpoints = []model.ServerEndpoint{{
		ID:        model.NewID(),
		Transport: "tcp",
		URL:       strings.Replace(listener.URL, "https://", "tcp://", 1),
		Source:    model.Manual,
	}}
	state, _ = db.Read()
	if _, err := db.Update(state.Revision, func(s *model.State) error {
		if s.ClusterID == "" {
			s.ClusterID = model.NewID()
		}
		s.ClusterCA = ca.PEM
		s.Servers = []model.Server{serverNode}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return db, srv, ca, listener, apiToken, updateDir
}

func createEnrollmentToken(t *testing.T, listener *httptest.Server, ca *pki.Authority, apiToken string) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"ttl_seconds": 600})
	req, err := http.NewRequest("POST", listener.URL+"/api/v1/enrollment-tokens", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := listener.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create enrollment token: HTTP %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Token      string `json:"token"`
		Invitation string `json:"invitation"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Token, out.Invitation
}

func TestAgentKeyFromEnvironment(t *testing.T) {
	t.Setenv(agentPrivateKeyEnv, "")
	if _, _, err := openAgentCache(""); err == nil {
		t.Fatal("empty key accepted")
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(agentPrivateKeyEnv, model.EncodeAgentPrivateKey(key)+"\n")
	cache, explicit, err := openAgentCache("")
	if err != nil || !explicit {
		t.Fatalf("open with key: explicit=%v, %v", explicit, err)
	}
	defer cache.Close()
	if !bytes.Equal(cache.PrivateKey(), key) {
		t.Fatal("configured key is not the identity")
	}

	t.Setenv(agentPrivateKeyEnv, "not-a-key")
	if _, _, err := openAgentCache(""); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestEnrollPersistsAndRunWithoutFlagsConnects(t *testing.T) {
	installTestDataPlaneHook(t)
	db, _, ca, listener, apiToken, _ := startTestController(t)
	_, invitation := createEnrollmentToken(t, listener, ca, apiToken)

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dataDir := filepath.Join(t.TempDir(), "agent-data")
	t.Setenv(agentPrivateKeyEnv, model.EncodeAgentPrivateKey(key))
	t.Setenv("GRAPHNET_AGENT_INVITATION", invitation)
	t.Setenv("GRAPHNET_SERVER", "")
	t.Setenv("GRAPHNET_CA", "")
	t.Setenv("GRAPHNET_ENROLLMENT_TOKEN", "")
	t.Setenv("GRAPHNET_NAME", "enrolled-node")

	if err := runAgentContext(t.Context(), []string{"enroll", "--data-dir", dataDir}); err != nil {
		t.Fatal("agent enroll failed:", err)
	}
	t.Setenv("GRAPHNET_AGENT_INVITATION", "")

	// Now start `agent run --data-dir <dir>` with zero bootstrap flags or env vars.
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- runAgentContext(ctx, []string{"run", "--data-dir", dataDir})
	}()

	deadline := time.Now().Add(10 * time.Second)
	connected := false
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", listener.URL+"/api/v1/telemetry", nil)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		resp, err := listener.Client().Do(req)
		if err == nil {
			var agents []model.AgentStatus
			_ = json.NewDecoder(resp.Body).Decode(&agents)
			resp.Body.Close()
			if len(agents) == 1 && agents[0].Connected {
				connected = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal("agent run exited with error:", err)
	}
	if !connected {
		state, _ := db.Read()
		t.Fatalf("enrolled agent never connected with --data-dir alone (agents in db: %d)", len(state.Agents))
	}
	if state, _ := db.Read(); len(state.Agents) != 1 || state.Agents[0].Name != "enrolled-node" {
		t.Fatalf("unexpected enrolled agent in db: %+v", state.Agents)
	}
}

func TestManagedServiceEnvBootstrapAndUpdateDelivery(t *testing.T) {
	installTestDataPlaneHook(t)
	prevVersion := version
	version = "v1.0.0"
	t.Cleanup(func() { version = prevVersion })

	launched := make(chan model.UpdateRequest, 1)
	prevLauncher := testLaunchUpdateHelper
	testLaunchUpdateHelper = func(_ updater.Receipt, stage string, req model.UpdateRequest) error {
		_ = os.Remove(stage)
		select {
		case launched <- req:
		default:
		}
		return nil
	}
	t.Cleanup(func() { testLaunchUpdateHelper = prevLauncher })

	db, _, ca, listener, apiToken, updateDir := startTestController(t)
	token, _ := createEnrollmentToken(t, listener, ca, apiToken)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dataDir := filepath.Join(t.TempDir(), "service-agent-data")
	t.Setenv(agentPrivateKeyEnv, model.EncodeAgentPrivateKey(key))
	t.Setenv("GRAPHNET_SERVER", listener.URL)
	t.Setenv("GRAPHNET_CA", caPath)
	t.Setenv("GRAPHNET_NAME", "systemd-node")
	t.Setenv("GRAPHNET_ENROLLMENT_TOKEN", token)

	// Simulate exact `service.go` invocation: managedServiceKey in context, only `--data-dir` in args.
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), managedServiceKey{}, "graphnet-agent"))
	done := make(chan error, 1)
	go func() {
		done <- runAgentContext(ctx, []string{"run", "--data-dir", dataDir})
	}()

	var agentID model.ID
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", listener.URL+"/api/v1/telemetry", nil)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		resp, err := listener.Client().Do(req)
		if err == nil {
			var agents []model.AgentStatus
			_ = json.NewDecoder(resp.Body).Decode(&agents)
			resp.Body.Close()
			if len(agents) == 1 && agents[0].Connected && agents[0].Update != nil && agents[0].Update.Managed {
				agentID = agents[0].AgentID
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if agentID == "" {
		cancel()
		<-done
		t.Fatal("managed service agent did not enroll, connect or report Managed=true")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "service.json")); err != nil {
		cancel()
		<-done
		t.Fatal("service.json not written by managedUpdater:", err)
	}

	// Stage a release binary in the controller's update cache and issue an UpdateRequest.
	payload := []byte("graphnet-staged-binary-v1.1.0")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(updateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(updateDir, digest), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	updateID := model.NewID()
	assetName := "graphnet-v1.1.0-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}
	asset := model.ReleaseAsset{
		Version: "v1.1.0",
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Name:    assetName,
		URL:     "https://github.com/eddiexyang/graphnet/releases/download/v1.1.0/" + assetName,
		SHA256:  digest,
		Size:    int64(len(payload)),
	}
	state, _ := db.Read()
	if _, err := db.Update(state.Revision, func(s *model.State) error {
		for i := range s.Agents {
			if s.Agents[i].ID == agentID {
				s.Agents[i].Update = &model.UpdateRequest{
					ID:        updateID,
					Source:    "server",
					Asset:     asset,
					CreatedAt: time.Now().UTC(),
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	patchReq, _ := http.NewRequest("PATCH", listener.URL+"/api/v1/agents/"+string(agentID), strings.NewReader(`{"name":"systemd-node-updated"}`))
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("Authorization", "Bearer "+apiToken)
	if patchResp, err := listener.Client().Do(patchReq); err != nil {
		t.Fatal(err)
	} else {
		patchResp.Body.Close()
	}

	select {
	case got := <-launched:
		if got.ID != updateID || got.Asset.Version != "v1.1.0" {
			t.Fatalf("unexpected update request delivered: %+v", got)
		}
	case <-time.After(10 * time.Second):
		cancel()
		<-done
		t.Fatal("controller UpdateRequest never reached agent Updater")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal("managed service run exited with error:", err)
	}

	// Restart with residual GRAPHNET_ENROLLMENT_TOKEN still set in env (and no GRAPHNET_SERVER/CA):
	// persisted registration must ignore the spent token and reconnect cleanly.
	t.Setenv("GRAPHNET_SERVER", "")
	t.Setenv("GRAPHNET_CA", "")
	ctx2, cancel2 := context.WithCancel(t.Context())
	done2 := make(chan error, 1)
	go func() {
		done2 <- runAgentContext(ctx2, []string{"run", "--data-dir", dataDir})
	}()
	reconnected := false
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", listener.URL+"/api/v1/telemetry", nil)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		resp, err := listener.Client().Do(req)
		if err == nil {
			var agents []model.AgentStatus
			_ = json.NewDecoder(resp.Body).Decode(&agents)
			resp.Body.Close()
			if len(agents) == 1 && agents[0].Connected {
				reconnected = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel2()
	if err := <-done2; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal("second run with residual token failed:", err)
	}
	if !reconnected {
		t.Fatal("agent failed to reconnect on second start with residual GRAPHNET_ENROLLMENT_TOKEN")
	}
}
