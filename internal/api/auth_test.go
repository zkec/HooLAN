package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func authRequest(router http.Handler, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestBrowserSessionCSRFAndLogout(t *testing.T) {
	router := NewRouter(nil, RouterOptions{Token: "correct-token", Logger: quietLogger()})
	initial := authRequest(router, "GET", "/api/auth/session", "", nil, "")
	var state sessionResponse
	if err := json.Unmarshal(initial.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Authenticated || !state.AuthRequired || state.CSRFToken != "" {
		t.Fatalf("initial=%+v", state)
	}
	bad := authRequest(router, "POST", "/api/auth/login", `{"token":"wrong"}`, nil, "")
	if bad.Code != 401 || len(bad.Result().Cookies()) != 0 {
		t.Fatalf("bad login=%d", bad.Code)
	}
	login := authRequest(router, "POST", "/api/auth/login", `{"token":"correct-token"}`, nil, "")
	if login.Code != 200 {
		t.Fatalf("login=%d %s", login.Code, login.Body.String())
	}
	if err := json.Unmarshal(login.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%v", cookies)
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 || cookie.Secure || cookie.Value == "correct-token" {
		t.Fatalf("unsafe cookie=%+v", cookie)
	}
	if !state.Authenticated || state.CSRFToken == "" || strings.Contains(login.Body.String(), "correct-token") {
		t.Fatalf("login state=%+v", state)
	}
	if result := authRequest(router, "POST", "/api/auth/logout", "", cookie, ""); result.Code != 403 {
		t.Fatalf("missing CSRF=%d", result.Code)
	}
	if result := authRequest(router, "GET", "/api/unknown", "", cookie, ""); result.Code != 404 {
		t.Fatalf("session access=%d", result.Code)
	}
	logout := authRequest(router, "POST", "/api/auth/logout", "", cookie, state.CSRFToken)
	if logout.Code != 200 || logout.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("logout=%d cookies=%v", logout.Code, logout.Result().Cookies())
	}
	if result := authRequest(router, "GET", "/api/unknown", "", cookie, ""); result.Code != 401 {
		t.Fatalf("revoked session access=%d", result.Code)
	}
}

func TestLoginOriginTLSAndThrottling(t *testing.T) {
	for _, secureProxy := range []bool{false, true} {
		router := NewRouter(nil, RouterOptions{Token: "token", SecureCookies: secureProxy, Logger: quietLogger()})
		cross := httptest.NewRequest("POST", "http://gateway/api/auth/login", strings.NewReader(`{"token":"token"}`))
		cross.Header.Set("Origin", "https://attacker.example")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, cross)
		if w.Code != 403 {
			t.Fatalf("cross-origin login=%d", w.Code)
		}
		r := httptest.NewRequest("POST", "https://gateway/api/auth/login", strings.NewReader(`{"token":"token"}`))
		r.Header.Set("Origin", "https://gateway")
		if secureProxy {
			r.TLS = nil
		} else {
			r.TLS = &tls.ConnectionState{}
		}
		w = httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 200 || !w.Result().Cookies()[0].Secure {
			t.Fatalf("HTTPS login=%d cookies=%v", w.Code, w.Result().Cookies())
		}
	}
	router := NewRouter(nil, RouterOptions{Token: "token", Logger: quietLogger()})
	for i := 0; i < maxLoginAttempts; i++ {
		if w := authRequest(router, "POST", "/api/auth/login", `{"token":"wrong"}`, nil, ""); w.Code != 401 {
			t.Fatalf("attempt %d=%d", i, w.Code)
		}
	}
	limited := authRequest(router, "POST", "/api/auth/login", `{"token":"token"}`, nil, "")
	if limited.Code != 429 || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("limit=%d", limited.Code)
	}
}

func TestSessionsExpireAndAreBounded(t *testing.T) {
	store := newSessionStore()
	id, session, err := store.create()
	if err != nil {
		t.Fatal(err)
	}
	session.expires = time.Now().Add(-time.Second)
	if store.get(id) != nil {
		t.Fatal("expired session accepted")
	}
	select {
	case <-session.done:
	default:
		t.Fatal("expired session not revoked")
	}
	for i := 0; i < maxSessions+20; i++ {
		if _, _, err := store.create(); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.sessions) != maxSessions {
		t.Fatalf("session count=%d", len(store.sessions))
	}
}

func TestBearerAndUnauthenticatedCompatibility(t *testing.T) {
	for _, token := range []string{"", "token"} {
		router := NewRouter(nil, RouterOptions{Token: token, Logger: quietLogger()})
		r := httptest.NewRequest("POST", "/api/auth/logout", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("token %q logout without browser CSRF=%d", token, w.Code)
		}
	}
}
