// Package webui serves embedded production static files and the Agent
// binaries this controller distributes.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed dist
var distFS embed.FS

// AgentAssetPrefix is where Agents download the binary of a release:
// /assets/agent/<version>/<os>-<arch>.
const AgentAssetPrefix = "/assets/agent/"

var (
	agentVersion  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	agentPlatform = regexp.MustCompile(`^[a-z0-9]{1,16}-[a-z0-9]{1,16}$`)
)

// Handler serves the embedded web UI, and the Agent binaries found in
// agentDirectory as <version>/<os>-<arch>. Only those names, regular files
// and real directories are served: nothing else on disk is reachable. An empty
// agentDirectory serves no binaries.
func Handler(agentDirectory string) http.Handler {
	root, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, AgentAssetPrefix) {
			serveAgent(w, r, agentDirectory)
			return
		}
		// Static assets do not bypass API authentication, and missing asset/API
		// paths never receive an HTML fallback masquerading as a successful API.
		if r.URL.Path != "/" && r.URL.Path != "/THIRD_PARTY_LICENSES.txt" && !strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		info, err := fs.Stat(root, name)
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Minute))
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		files.ServeHTTP(w, r)
	})
}

func serveAgent(w http.ResponseWriter, r *http.Request, directory string) {
	version, platform, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, AgentAssetPrefix), "/")
	if directory == "" || !ok || !agentVersion.MatchString(version) || !agentPlatform.MatchString(platform) {
		http.NotFound(w, r)
		return
	}
	dir := filepath.Join(directory, version)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		http.NotFound(w, r)
		return
	}
	name := filepath.Join(dir, platform)
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Minute))
	http.ServeContent(w, r, platform, info.ModTime(), f)
}
