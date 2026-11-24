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

	handler := Handler()
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
