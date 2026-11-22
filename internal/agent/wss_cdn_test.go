package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/sockets"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"github.com/eddiexyang/graphnet/internal/transport"
	"github.com/eddiexyang/graphnet/internal/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func testCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

func testLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// TestWSSDirectAndWSStreamTransfer verifies both plain WS and direct WSS carry
// GraphNet streams with AES-128-GCM end-to-end encryption.
func TestWSSDirectAndWSStreamTransfer(t *testing.T) {
	for _, carrier := range []model.Transport{model.WS, model.WSS} {
		t.Run(string(carrier), func(t *testing.T) {
			_, devices, state := graphAgents(t, carrier, streamOptions{}, 3, 2, func(s *model.State) {
				s.Networks[0].Cipher = model.AES128GCM
				for i := range s.Agents {
					if len(s.Agents[i].Endpoints) > 0 {
						s.Agents[i].Endpoints[0].URL += "/gn"
					}
				}
			})
			transferApplication(t, devices[0], devices[2], state.Networks[0].Nodes[2].Address)
		})
	}
}

// TestWSSThroughCDNMiddleboxWithMTLSOrigin simulates a full CDN middlebox:
//   Client --(TLS 1.3 X25519 + WSS)--> CDN Edge --(mTLS TLS 1.3 X25519 + WSS)--> Origin Agent
// Inside the WebSocket byte stream, GraphNet runs Noise XX + AES-128-GCM + mux streams.
func TestWSSThroughCDNMiddleboxWithMTLSOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Separate PKIs: public CDN CA, origin server CA, and CDN-to-origin mTLS client CA.
	cdnCA, cdnCAKey, cdnRoots := testCA(t, "Simulated CDN Public CA")
	originCA, originCAKey, originRoots := testCA(t, "Simulated Origin CA")
	mtlsCA, mtlsCAKey, mtlsClientCAs := testCA(t, "Simulated CDN Origin-Pull mTLS CA")

	cdnServerCert := testLeafCert(t, cdnCA, cdnCAKey, "cdn.graphnet.test", x509.ExtKeyUsageServerAuth)
	originServerCert := testLeafCert(t, originCA, originCAKey, "origin.graphnet.test", x509.ExtKeyUsageServerAuth)
	cdnClientCert := testLeafCert(t, mtlsCA, mtlsCAKey, "cdn-edge.graphnet.test", x509.ExtKeyUsageClientAuth)

	// Start Origin Agent (node 1) requiring mTLS client certs on incoming WSS links.
	originPort := testutil.AgentPort(t)
	var originDev *kernelTUN
	originSeed := make([]byte, ed25519.SeedSize)
	originSeed[0] = 2
	originKey := ed25519.NewKeyFromSeed(originSeed)

	originDP, err := NewDataPlane(ctx, originKey, DataPlaneOptions{
		BindHost:        "127.0.0.1",
		OriginClientCAs: mtlsClientCAs,
		OriginTLS: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519},
			Certificates:     []tls.Certificate{originServerCert},
		},
		TunnelFactory: func(cfg tunnel.Config) (tunnel.Device, error) {
			d, err := newKernelTUN(cfg, true)
			originDev = d
			return d, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { originDP.Close() })

	// Start simulated CDN middlebox: terminates client TLS 1.3 (X25519),
	// upgrades WebSocket, and dials Origin Agent via mTLS TLS 1.3 (X25519).
	var clientTLSOK, originMTLSOK atomic.Bool
	cdnTransport := &http.Transport{
		ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519},
			ServerName:       "origin.graphnet.test",
			RootCAs:          originRoots,
			Certificates:     []tls.Certificate{cdnClientCert},
			VerifyConnection: func(cs tls.ConnectionState) error {
				if cs.Version == tls.VersionTLS13 && cs.CurveID == tls.X25519 {
					originMTLSOK.Store(true)
				}
				return nil
			},
		},
	}
	cdnHTTPClient := &http.Client{Transport: cdnTransport}
	originWSURL := fmt.Sprintf("wss://127.0.0.1:%d/edge", originPort)

	cdnMux := http.NewServeMux()
	cdnMux.HandleFunc("/edge", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.Version == tls.VersionTLS13 && r.TLS.CurveID == tls.X25519 {
			clientTLSOK.Store(true)
		}
		proto := r.Header.Get("Sec-WebSocket-Protocol")
		downstream, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:    []string{proto},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		downstream.SetReadLimit(4 << 20)
		defer downstream.CloseNow()

		upstream, resp, err := websocket.Dial(r.Context(), originWSURL, &websocket.DialOptions{
			HTTPClient:      cdnHTTPClient,
			Subprotocols:    []string{proto},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			return
		}
		upstream.SetReadLimit(4 << 20)
		defer upstream.CloseNow()

		dnc := websocket.NetConn(r.Context(), downstream, websocket.MessageBinary)
		unc := websocket.NetConn(r.Context(), upstream, websocket.MessageBinary)
		done := make(chan struct{}, 2)
		go func() {
			buf := make([]byte, 64<<10)
			_, _ = io.CopyBuffer(unc, dnc, buf)
			_ = unc.Close()
			done <- struct{}{}
		}()
		go func() {
			buf := make([]byte, 64<<10)
			_, _ = io.CopyBuffer(dnc, unc, buf)
			_ = dnc.Close()
			done <- struct{}{}
		}()
		<-done
		<-done
	})

	rawLN, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cdnLN := tls.NewListener(rawLN, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		NextProtos:       []string{"http/1.1"},
		Certificates:     []tls.Certificate{cdnServerCert},
	})
	cdnSrv := &http.Server{Handler: cdnMux}
	go cdnSrv.Serve(cdnLN)
	t.Cleanup(func() { cdnSrv.Close() })
	cdnPort := rawLN.Addr().(*net.TCPAddr).Port

	// Build 2-node topology: Node 0 (Client) -> CDN WSS -> Node 1 (Origin), AES-128-GCM.
	full := testutil.Topology()
	state := model.EmptyState()
	state.Revision = 7
	clientAgent := full.Agents[0]
	originAgent := full.Agents[1]
	clientAgent.Endpoints = []model.Endpoint{}
	originAgent.ListenPort = originPort
	originAgent.Endpoints = []model.Endpoint{{
		ID:        testutil.ID(31),
		Transport: model.WSS,
		Source:    model.Manual,
		URL:       fmt.Sprintf("wss://cdn.graphnet.test:%d/edge", cdnPort),
	}}
	state.Agents = []model.Agent{clientAgent, originAgent}

	netCfg := full.Networks[0]
	netCfg.Cipher = model.AES128GCM
	netCfg.Nodes = full.Networks[0].Nodes[:2]
	netCfg.Nodes[0].Client = true
	netCfg.Edges = full.Networks[0].Edges[:1]
	netCfg.Edges[0].Transports = []model.Transport{model.WSS}
	state.Networks = []model.Network{netCfg}

	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}

	// Apply snapshot to Origin Agent first.
	originSnap, err := routing.Compile(state, originAgent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := originDP.Apply(ctx, originSnap); err != nil {
		t.Fatal(err)
	}

	// Verify direct TLS dial to Origin WITHOUT mTLS client cert is rejected.
	unauthConn, dialErr := tls.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", originPort), &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		ServerName:       "origin.graphnet.test",
		RootCAs:          originRoots,
	})
	if dialErr == nil {
		_, readErr := unauthConn.Read(make([]byte, 1))
		unauthConn.Close()
		if readErr == nil {
			t.Fatal("origin accepted TLS connection without mTLS client certificate")
		}
	}

	// Start Client Agent (node 0) resolving cdn.graphnet.test -> 127.0.0.1 and trusting cdnRoots.
	clientCtx := sockets.With(ctx, sockets.Hooks{
		Lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			if host == "cdn.graphnet.test" {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return nil, fmt.Errorf("unexpected host %s", host)
		},
	})
	clientSeed := make([]byte, ed25519.SeedSize)
	clientSeed[0] = 1
	clientKey := ed25519.NewKeyFromSeed(clientSeed)
	var clientDev *kernelTUN
	clientDP, err := NewDataPlane(clientCtx, clientKey, DataPlaneOptions{
		BindHost:       "127.0.0.1",
		Embedded:       true,
		WebSocketRoots: cdnRoots,
		TunnelFactory: func(cfg tunnel.Config) (tunnel.Device, error) {
			d, err := newKernelTUN(cfg, true)
			clientDev = d
			return d, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientDP.Close() })

	clientSnap, err := routing.Compile(state, clientAgent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientDP.Apply(clientCtx, clientSnap); err != nil {
		t.Fatal(err)
	}
	clientDev.attachEmbeddedClient(clientCtx, clientDP)

	// Wait for WSS link through CDN + mTLS origin pull to come up with streams.
	waitFor(t, 15*time.Second, "WSS CDN mTLS link ready", func() bool {
		st := clientDP.state.Load()
		if st == nil || st.mesh == nil {
			return false
		}
		return st.mesh.StreamsAvailable(netCfg.ID, netCfg.Nodes[1].ID)
	})
	if !clientTLSOK.Load() {
		t.Fatal("client -> CDN did not negotiate TLS 1.3 X25519")
	}
	if !originMTLSOK.Load() {
		t.Fatal("CDN -> origin did not negotiate mTLS TLS 1.3 X25519")
	}

	// Send 1 MiB bidirectional TCP stream through Embedded Client -> CDN WSS -> mTLS Origin.
	target := netCfg.Nodes[1].Address
	ln, err := gonet.ListenTCP(originDev.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 9443}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	payload := make([]byte, 1<<20)
	rand.Read(payload)
	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		raw, err := io.ReadAll(c)
		if err == nil && !bytes.Equal(raw, payload) {
			err = errors.New("payload mismatch")
		}
		if err == nil {
			_, err = c.Write([]byte("cdn-mtls-ok"))
		}
		if err == nil {
			err = c.(*gonet.TCPConn).CloseWrite()
		}
		srvErr <- err
	}()

	dctx, dcancel := context.WithTimeout(clientCtx, 15*time.Second)
	defer dcancel()
	conn, err := clientDev.dialTCP(dctx, tcpip.AddrFrom4(target.As4()), 9443, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "cdn-mtls-ok" {
		t.Fatalf("reply = %q, err = %v", got, err)
	}
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
	_ = transport.WebSocketProtocol(model.WSS)
}
