package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type usageLockWriter struct {
	*httptest.ResponseRecorder
	service  *Service
	unlocked bool
}

func (w *usageLockWriter) Write(p []byte) (int, error) {
	w.unlocked = w.service.mu.TryLock()
	if w.unlocked {
		w.service.mu.Unlock()
	}
	return w.ResponseRecorder.Write(p)
}
func TestUsageReleasesStateLockBeforeHTTPWrite(t *testing.T) {
	h := newLocalHarness(t, nil, nil)
	w := &usageLockWriter{ResponseRecorder: httptest.NewRecorder(), service: h.svc}
	(&handlers{svc: h.svc}).usage(w, httptest.NewRequest(http.MethodGet, "/api/usage", nil))
	if !w.unlocked {
		t.Fatal("slow HTTP client can block state updates")
	}
}

func TestTelegramReleasesLocksBeforeHTTPWrite(t *testing.T) {
	h := newLocalHarness(t, nil, nil)
	for _, tc := range []struct {
		method, body string
		status       int
	}{{"GET", "", 200}, {"PUT", `{"enabled":false}`, 200}, {"PUT", `{"enabled":true,"token":"bad"}`, 400}} {
		w := &usageLockWriter{ResponseRecorder: httptest.NewRecorder(), service: h.svc}
		h.svc.telegram(w, httptest.NewRequest(tc.method, "/api/telegram", strings.NewReader(tc.body)))
		if !w.unlocked || w.Code != tc.status {
			t.Fatalf("response locks/status: %v %d", w.unlocked, w.Code)
		}
	}
}
