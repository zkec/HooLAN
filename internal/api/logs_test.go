package api

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hoolan/internal/logstream"
)

func nextLog(t *testing.T, reader *bufio.Reader) logstream.Entry {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE: %v", err)
		}
		if strings.HasPrefix(line, "data: ") {
			var entry logstream.Entry
			if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data: "))), &entry); err != nil {
				t.Fatal(err)
			}
			return entry
		}
	}
}

func TestSSEReplayLiveWritesAndLogoutThroughRouter(t *testing.T) {
	hub := logstream.New("token")
	defer hub.Close()
	hub.Publish("INFO", "service", "first")
	hub.Publish("ERROR", "sing-box", "second token")
	srv := httptest.NewUnstartedServer(NewRouter(nil, RouterOptions{Token: "token", Logs: hub, Logger: quietLogger()}))
	srv.Config.WriteTimeout = 50 * time.Millisecond
	srv.Start()
	defer srv.Close()
	client := srv.Client()
	client.Timeout = 3 * time.Second
	login, err := client.Post(srv.URL+"/api/auth/login", "application/json", strings.NewReader(`{"token":"token"}`))
	if err != nil {
		t.Fatal(err)
	}
	var state sessionResponse
	if err := json.NewDecoder(login.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	cookie := login.Cookies()[0]
	req, _ := http.NewRequest("GET", srv.URL+"/api/logs", nil)
	req.AddCookie(cookie)
	req.Header.Set("Last-Event-ID", "1")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("stream response=%d headers=%v", response.StatusCode, response.Header)
	}
	reader := bufio.NewReader(response.Body)
	entry := nextLog(t, reader)
	if entry.ID != 2 || entry.Source != "sing-box" || strings.Contains(entry.Message, "token") {
		t.Fatalf("replay=%+v", entry)
	}
	// An ordinary handler would lose its connection to WriteTimeout by now.
	time.Sleep(100 * time.Millisecond)
	hub.Publish("INFO", "service", "third")
	if entry := nextLog(t, reader); entry.ID != 3 {
		t.Fatalf("live=%+v", entry)
	}
	logout, _ := http.NewRequest("POST", srv.URL+"/api/auth/logout", nil)
	logout.AddCookie(cookie)
	logout.Header.Set("X-CSRF-Token", state.CSRFToken)
	result, err := client.Do(logout)
	if err != nil {
		t.Fatal(err)
	}
	result.Body.Close()
	if result.StatusCode != 200 {
		t.Fatalf("logout=%d", result.StatusCode)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("revoked stream did not close cleanly: %v", err)
	}
}

func TestSSESessionExpiryTerminatesStream(t *testing.T) {
	hub := logstream.New()
	defer hub.Close()
	h := &handlers{opts: RouterOptions{Token: "token", Logs: hub}, auth: newSessionStore(), log: quietLogger()}
	id, session, err := h.auth.create()
	if err != nil {
		t.Fatal(err)
	}
	session.expires = time.Now().Add(100 * time.Millisecond)
	srv := httptest.NewServer(h.logRequests(h.authenticate(http.HandlerFunc(h.logs))))
	defer srv.Close()
	client := srv.Client()
	client.Timeout = 2 * time.Second
	req, _ := http.NewRequest("GET", srv.URL+"/api/logs", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("stream status=%d", response.StatusCode)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatalf("expired stream did not close: %v", err)
	}
}
