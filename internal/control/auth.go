package control

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/store"
	"golang.org/x/crypto/scrypt"
)

const cookieName = "graphnet_session"

type passwordRecord struct {
	Salt []byte `json:"salt"`
	Hash []byte `json:"hash"`
}
type session struct {
	CSRF    string
	Expires time.Time
}
type attempt struct {
	Count int
	Until time.Time
}
type auth struct {
	password       passwordRecord
	apiTokenSet    bool
	apiToken       [32]byte
	mu             sync.Mutex
	sessions       map[[32]byte]session
	loginAttempts  map[string]attempt
	enrollAttempts map[string]attempt
	slots          chan struct{}
}

func randomToken() string {
	var raw [32]byte
	rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}
func tokenHash(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func ValidateAdminPassword(password string) error {
	if len(password) < 12 || len(password) > 1024 {
		return errors.New("admin password must be 12–1024 bytes")
	}
	switch strings.ToLower(strings.TrimSpace(password)) {
	case "replace-before-first-start", "replace-with-your-own-password", "changeme", "password123456":
		return errors.New("admin password cannot be a placeholder example value")
	}
	return nil
}

// ResetPassword replaces the stored admin password hash in db.
func ResetPassword(db *store.Store, password string) error {
	if err := ValidateAdminPassword(password); err != nil {
		return err
	}
	var rec passwordRecord
	rec.Salt = make([]byte, 32)
	if _, err := rand.Read(rec.Salt); err != nil {
		return err
	}
	hash, err := scrypt.Key([]byte(password), rec.Salt, 32768, 8, 1, 32)
	if err != nil {
		return err
	}
	rec.Hash = hash
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return db.WriteRecords(func(r *store.Records) error {
		return r.Put("admin-password", raw)
	})
}

func newAuth(db *store.Store, password, apiToken string) (*auth, error) {
	a := &auth{
		sessions:       map[[32]byte]session{},
		loginAttempts:  map[string]attempt{},
		enrollAttempts: map[string]attempt{},
		slots:          make(chan struct{}, 4),
	}
	if tok := strings.TrimSpace(apiToken); tok != "" {
		a.apiTokenSet = true
		a.apiToken = tokenHash(tok)
	}
	err := db.WriteRecords(func(r *store.Records) error {
		if raw := r.Get("admin-password"); raw != nil {
			if err := json.Unmarshal(raw, &a.password); err != nil {
				return err
			}
			if len(a.password.Salt) != 32 || len(a.password.Hash) != 32 {
				return errors.New("invalid stored password hash")
			}
			return nil
		}
		if err := ValidateAdminPassword(password); err != nil {
			return fmt.Errorf("first startup: %w", err)
		}
		a.password.Salt = make([]byte, 32)
		rand.Read(a.password.Salt)
		hash, err := scrypt.Key([]byte(password), a.password.Salt, 32768, 8, 1, 32)
		if err != nil {
			return err
		}
		a.password.Hash = hash
		raw, err := json.Marshal(a.password)
		if err != nil {
			return err
		}
		return r.Put("admin-password", raw)
	})
	return a, err
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return err == nil && u.Scheme == scheme && u.Host == r.Host && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
func (a *auth) allowAttempt(r *http.Request) bool {
	return a.allowBucketAttempt(r, a.loginAttempts)
}

func (a *auth) allowEnrollAttempt(r *http.Request) bool {
	return a.allowBucketAttempt(r, a.enrollAttempts)
}

func (a *auth) allowBucketAttempt(r *http.Request, table map[string]attempt) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	var oldestKey string
	var oldestUntil time.Time
	for key, v := range table {
		if now.After(v.Until) {
			delete(table, key)
			continue
		}
		if oldestKey == "" || v.Until.Before(oldestUntil) {
			oldestKey, oldestUntil = key, v.Until
		}
	}
	v, exists := table[host]
	if !exists {
		if len(table) >= 4096 && oldestKey != "" {
			delete(table, oldestKey)
		}
		v.Until = now.Add(time.Minute)
	}
	v.Count++
	table[host] = v
	return v.Count <= 10
}
func (a *auth) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		fail(w, 403, "cross-origin request rejected")
		return
	}
	if !a.allowAttempt(r) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "too many login attempts")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) > 1024 {
		fail(w, 401, "invalid password")
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		fail(w, 429, "too many login attempts")
		return
	}
	hash, err := scrypt.Key([]byte(in.Password), a.password.Salt, 32768, 8, 1, 32)
	if err != nil || subtle.ConstantTimeCompare(hash, a.password.Hash) != 1 {
		fail(w, 401, "invalid password")
		return
	}
	token := randomToken()
	s := session{CSRF: randomToken(), Expires: time.Now().Add(12 * time.Hour)}
	a.mu.Lock()
	now := time.Now()
	var oldestSess [32]byte
	var hasOldest bool
	var oldestExp time.Time
	for k, v := range a.sessions {
		if now.After(v.Expires) {
			delete(a.sessions, k)
			continue
		}
		if !hasOldest || v.Expires.Before(oldestExp) {
			oldestSess, oldestExp, hasOldest = k, v.Expires, true
		}
	}
	// Logging in rotates an existing session in the same browser.
	if c, err := r.Cookie(cookieName); err == nil {
		delete(a.sessions, tokenHash(c.Value))
	}
	if len(a.sessions) >= 256 && hasOldest {
		delete(a.sessions, oldestSess)
	}
	a.sessions[tokenHash(token)] = s
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: s.Expires, MaxAge: 43200})
	respond(w, 200, map[string]string{"csrf_token": s.CSRF})
}
func (a *auth) find(r *http.Request) (session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) > 128 {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := tokenHash(c.Value)
	s, ok := a.sessions[key]
	if ok && time.Now().After(s.Expires) {
		delete(a.sessions, key)
		return session{}, false
	}
	return s, ok
}
func (a *auth) validBearer(r *http.Request) bool {
	if !a.apiTokenSet {
		return false
	}
	hdr := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(hdr, prefix) {
		return false
	}
	tok := strings.TrimSpace(hdr[len(prefix):])
	if tok == "" || len(tok) > 1024 {
		return false
	}
	sum := tokenHash(tok)
	return subtle.ConstantTimeCompare(sum[:], a.apiToken[:]) == 1
}
func (a *auth) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.validBearer(r) {
			next(w, r)
			return
		}
		s, ok := a.find(r)
		if !ok {
			fail(w, 401, "authentication required")
			return
		}
		if !sameOrigin(r) {
			fail(w, 403, "cross-origin request rejected")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
			fail(w, 403, "invalid CSRF token")
			return
		}
		next(w, r)
	}
}
func (a *auth) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.mu.Lock()
		delete(a.sessions, tokenHash(c.Value))
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(204)
}
