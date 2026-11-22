package client

import "testing"

func TestParseServerURL(t *testing.T) {
	cases := []struct {
		raw, explicit string
		wantOrigin    string
		wantTransport string
	}{
		{"https://cp.example.com", "", "https://cp.example.com", "https"},
		{"tcp://127.0.0.1:8443", "", "https://127.0.0.1:8443", "tcp"},
		{"ws://cp.example.com:8080", "", "https://cp.example.com:8080", "websocket"},
		{"wss://cp.example.com", "", "https://cp.example.com", "wss"},
		{"grpc://10.0.0.1:8443", "", "https://10.0.0.1:8443", "grpc"},
		{"https://127.0.0.1:8443", "tcp", "https://127.0.0.1:8443", "tcp"},
	}
	for _, tc := range cases {
		origin, tr, err := parseServerURL(tc.raw, tc.explicit)
		if err != nil {
			t.Fatalf("parseServerURL(%q, %q): %v", tc.raw, tc.explicit, err)
		}
		if origin != tc.wantOrigin || tr != tc.wantTransport {
			t.Fatalf("parseServerURL(%q, %q) = (%q, %q), want (%q, %q)", tc.raw, tc.explicit, origin, tr, tc.wantOrigin, tc.wantTransport)
		}
	}
	if _, _, err := parseServerURL("ftp://example.com", ""); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}
