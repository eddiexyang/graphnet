package webui

import (
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticFiles(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	if err := os.MkdirAll(filepath.Join(directory, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "private.txt"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "assets", "cwd-secret.js"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(directory, "private.txt"), filepath.Join(directory, "assets", "link.js"))

	sub, err := fs.Sub(distFS, "dist/assets")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil || len(entries) == 0 {
		t.Fatalf("embedded dist/assets empty: %v", err)
	}
	assetPath := "/assets/" + entries[0].Name()

	handler := Handler(filepath.Join(directory, "assets", "agent"))
	for _, tc := range []struct {
		method, path, rangeHeader string
		status                    int
	}{
		{"GET", "/", "", 200},
		{"GET", "/THIRD_PARTY_LICENSES.txt", "", 200},
		{"GET", assetPath, "", 200},
		{"HEAD", assetPath, "", 200},
		{"GET", assetPath, "bytes=0-3", 206},
		{"GET", "/assets/", "", 404},
		{"GET", "/assets/cwd-secret.js", "", 404},
		{"GET", "/assets/link.js", "", 404},
		{"GET", "/assets/../private.txt", "", 404},
		{"GET", "/private.txt", "", 404},
		{"GET", "/api/v1/state", "", 404},
	} {
		t.Run(tc.method+tc.path+tc.rangeHeader, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.rangeHeader != "" {
				request.Header.Set("Range", tc.rangeHeader)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status=%d, want %d", response.Code, tc.status)
			}
			if tc.path == "/" && !strings.Contains(response.Body.String(), "<!doctype html>") && !strings.Contains(response.Body.String(), "<html") {
				t.Fatalf("unexpected root HTML: %q", response.Body.String())
			}
		})
	}
}

// The controller distributes Agent binaries from its asset directory; nothing
// else there or around it is reachable through that path.
func TestAgentBinaries(t *testing.T) {
	directory := t.TempDir()
	agents := filepath.Join(directory, "agent")
	release := filepath.Join(agents, "sha-0123")
	if err := os.MkdirAll(release, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "linux-amd64"), []byte("0123456789"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(directory, "secret"), filepath.Join(release, "linux-arm64"))
	_ = os.Symlink(release, filepath.Join(agents, "sha-link"))

	handler := Handler(agents)
	for _, tc := range []struct {
		method, path, rangeHeader string
		status                    int
		body                      string
	}{
		{"GET", "/assets/agent/sha-0123/linux-amd64", "", 200, "0123456789"},
		{"HEAD", "/assets/agent/sha-0123/linux-amd64", "", 200, ""},
		{"GET", "/assets/agent/sha-0123/linux-amd64", "bytes=2-4", 206, "234"},
		{"GET", "/assets/agent/sha-0123/linux-arm64", "", 404, ""},
		{"GET", "/assets/agent/sha-link/linux-amd64", "", 404, ""},
		{"GET", "/assets/agent/sha-0123/", "", 404, ""},
		{"GET", "/assets/agent/sha-0123", "", 404, ""},
		{"GET", "/assets/agent/../secret", "", 404, ""},
		{"GET", "/assets/agent/sha-0123/..%2f..%2fsecret", "", 404, ""},
		{"GET", "/assets/agent/../agent/sha-0123/linux-amd64", "", 404, ""},
		{"GET", "/assets/agent/missing/linux-amd64", "", 404, ""},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.rangeHeader != "" {
			req.Header.Set("Range", tc.rangeHeader)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status || tc.body != "" && rec.Body.String() != tc.body {
			t.Errorf("%s %s: %d %q, want %d %q", tc.method, tc.path, rec.Code, rec.Body.String(), tc.status, tc.body)
		}
	}
	if rec := httptest.NewRecorder(); true {
		Handler("").ServeHTTP(rec, httptest.NewRequest("GET", "/assets/agent/sha-0123/linux-amd64", nil))
		if rec.Code != 404 {
			t.Errorf("served a binary without an asset directory: %d", rec.Code)
		}
	}
}
