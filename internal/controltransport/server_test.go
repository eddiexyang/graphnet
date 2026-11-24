package controltransport_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/controltransport"
)

func TestPlainHTTPReachesNoApplicationHandler(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var reached atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			reached.Add(1)
		}
		w.WriteHeader(http.StatusTeapot)
	})
	server := controltransport.NewServer(listener, handler, certificateServer.TLS)
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		server.Close()
		if err := <-done; !controltransport.Closed(err) {
			t.Error(err)
		}
		server.Wait()
	})
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	for _, path := range []string{
		"/",
		"/assets/binary",
		"/api/v1/enroll",
		"/api/v1/agent/challenge",
		"/api/v1/agent/control",
		"/api/v1/agent/registration",
		"/api/v1/agent/update/latest",
		"/api/v1/agent/update/download/123",
		"/api/v1/state",
		"/api/v1/login",
	} {
		response, err := client.Get("http://" + listener.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUpgradeRequired {
			t.Errorf("%s: status=%d, want %d", path, response.StatusCode, http.StatusUpgradeRequired)
		}
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("plaintext requests reached application handler %d times", n)
	}

	secure := certificateServer.Client()
	defer secure.CloseIdleConnections()
	response, err := secure.Get("https://" + listener.Addr().String() + "/api/private")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTeapot {
		t.Fatal("existing TLS handler stopped working")
	}
}
