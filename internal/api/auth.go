package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "proxy_manager_session"
	sessionLifetime   = 12 * time.Hour
	maxSessions       = 128
	maxLoginClients   = 1024
	loginWindow       = time.Minute
	maxLoginAttempts  = 10
)

type browserSession struct {
	csrf    string
	expires time.Time
	done    chan struct{}
}

type loginAttempts struct {
	start time.Time
	count int
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*browserSession
	attempts map[string]loginAttempts
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*browserSession), attempts: make(map[string]loginAttempts)}
}

func secureEqual(a, b string) bool {
	// Hash first so the constant-time comparison also has a fixed input length.
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

func randomSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (s *sessionStore) removeLocked(id string) {
	if session := s.sessions[id]; session != nil {
		delete(s.sessions, id)
		close(session.done)
	}
}

func (s *sessionStore) get(id string) *browserSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessions[id]
	if session != nil && !time.Now().Before(session.expires) {
		s.removeLocked(id)
		return nil
	}
	return session
}

func (s *sessionStore) create() (string, *browserSession, error) {
	id, err := randomSecret()
	if err != nil {
		return "", nil, err
	}
	csrf, err := randomSecret()
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var oldestID string
	var oldestTime time.Time
	for key, session := range s.sessions {
		if !now.Before(session.expires) {
			s.removeLocked(key)
			continue
		}
		if oldestID == "" || session.expires.Before(oldestTime) {
			oldestID, oldestTime = key, session.expires
		}
	}
	if len(s.sessions) >= maxSessions {
		s.removeLocked(oldestID)
	}
	session := &browserSession{csrf: csrf, expires: now.Add(sessionLifetime), done: make(chan struct{})}
	s.sessions[id] = session
	return id, session, nil
}

func (s *sessionStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(id)
}

func (s *sessionStore) allowLogin(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, attempt := range s.attempts {
		if now.Sub(attempt.start) >= loginWindow {
			delete(s.attempts, key)
		}
	}
	attempt, exists := s.attempts[host]
	if !exists {
		// Refuse new buckets when full instead of letting attackers evict their
		// own throttling state by cycling addresses. Never trust X-Forwarded-For.
		if len(s.attempts) >= maxLoginClients {
			return false
		}
		attempt.start = now
	}
	attempt.count++
	s.attempts[host] = attempt
	return attempt.count <= maxLoginAttempts
}

type sessionContextKey struct{}

type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	AuthRequired  bool   `json:"auth_required"`
	CSRFToken     string `json:"csrf_token"`
}

func (h *handlers) requestSession(r *http.Request) *browserSession {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	return h.auth.get(cookie.Value)
}

func (h *handlers) bearerOK(r *http.Request) bool {
	v := r.Header.Get("Authorization")
	return strings.HasPrefix(v, "Bearer ") && secureEqual(strings.TrimPrefix(v, "Bearer "), h.opts.Token)
}

func (h *handlers) sameOrigin(r *http.Request) bool {
	// Browsers send Origin on mutations. Non-browser API clients may omit it.
	// Fetch metadata also blocks cross-site requests when Origin is absent.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil || h.opts.SecureCookies {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

func (h *handlers) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api" && !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !h.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross-origin API request denied")
			return
		}
		if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/session" || h.opts.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" {
			if !h.bearerOK(r) {
				writeError(w, http.StatusUnauthorized, "invalid bearer token")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		session := h.requestSession(r)
		if session == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !secureEqual(r.Header.Get("X-CSRF-Token"), session.csrf) {
				writeError(w, http.StatusForbidden, "invalid CSRF token")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, session)))
	})
}

func (h *handlers) authSession(w http.ResponseWriter, r *http.Request) {
	response := sessionResponse{AuthRequired: h.opts.Token != "", Authenticated: h.opts.Token == ""}
	if h.opts.Token != "" {
		if session := h.requestSession(r); session != nil {
			response.Authenticated, response.CSRFToken = true, session.csrf
		} else if h.bearerOK(r) {
			response.Authenticated = true
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if h.opts.Token == "" {
		h.authSession(w, r)
		return
	}
	if !h.auth.allowLogin(r.RemoteAddr) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many login attempts; retry in one minute")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid login request")
		return
	}
	if !secureEqual(body.Token, h.opts.Token) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	id, session, err := h.auth.create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	// Rotate any current session so previously opened streams lose access.
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		h.auth.remove(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: id, Path: "/api/", HttpOnly: true,
		Secure: r.TLS != nil || h.opts.SecureCookies, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionLifetime.Seconds()), Expires: session.expires})
	writeJSON(w, http.StatusOK, sessionResponse{Authenticated: true, AuthRequired: true, CSRFToken: session.csrf})
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		h.auth.remove(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/api/", HttpOnly: true,
		Secure: r.TLS != nil || h.opts.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1,
		Expires: time.Unix(1, 0)})
	writeJSON(w, http.StatusOK, sessionResponse{Authenticated: h.opts.Token == "", AuthRequired: h.opts.Token != ""})
}
