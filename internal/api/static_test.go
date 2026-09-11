package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The embed pattern is resolved at build time, so a missing or renamed asset is
// a compile-or-startup failure rather than a 404 in production. This asserts the
// set we actually reference from index.html made it in.
func TestEmbeddedAssetsLoaded(t *testing.T) {
	if initErr != nil {
		t.Fatalf("loadAssets: %v", initErr)
	}
	for _, want := range []string{"/index.html", "/app.js", "/style.css", "/login.html", "/login.js", "/preferences.js", "/i18n.js"} {
		a, ok := assets[want]
		if !ok {
			t.Errorf("asset %s not embedded", want)
			continue
		}
		if len(a.body) == 0 {
			t.Errorf("asset %s is empty", want)
		}
		if a.etag == "" {
			t.Errorf("asset %s has no etag", want)
		}
	}
	if got := assets["/app.js"].contentType; !strings.HasPrefix(got, "text/javascript") {
		// text/plain here means browsers refuse to execute the file.
		t.Errorf("app.js content type = %q, want text/javascript", got)
	}
}

func TestRootServesDashboard(t *testing.T) {
	h := newHarness(t, testNodes(), nil)

	for _, path := range []string{"/", "/index.html"} {
		resp, err := h.srv.Client().Get(h.srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		buf, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s content type = %q, want text/html", path, ct)
		}
		if !strings.Contains(string(buf), "<title>Proxy Manager</title>") {
			t.Errorf("GET %s did not return the dashboard", path)
		}
		if resp.Header.Get("ETag") == "" {
			t.Errorf("GET %s has no ETag", path)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s is missing nosniff", path)
		}
	}
}

// A conditional reload must not resend the whole page: the Pi serves this over
// a LAN to a browser that polls, and there is no Last-Modified on embedded
// files to fall back on.
func TestStaticRevalidatesWithETag(t *testing.T) {
	h := newHarness(t, testNodes(), nil)

	resp, err := h.srv.Client().Get(h.srv.URL + "/app.js")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on /app.js")
	}

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app.js", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("conditional get: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("conditional GET = %d, want 304", resp2.StatusCode)
	}
}

// The static handler is the catch-all, so it sees unmatched /api paths. Serving
// index.html there would hand a JSON client HTML under a 200.
func TestUnknownAPIRouteStaysJSON(t *testing.T) {
	h := newHarness(t, testNodes(), nil)

	code, body := h.do(http.MethodGet, "/api/does-not-exist", "")
	if code != http.StatusNotFound {
		t.Errorf("unknown /api route = %d, want 404", code)
	}
	if body["error"] == nil {
		t.Errorf("unknown /api route body = %v, want a JSON error", body)
	}
}

func TestUnknownStaticPathIs404(t *testing.T) {
	h := newHarness(t, testNodes(), nil)

	resp, err := h.srv.Client().Get(h.srv.URL + "/nope.js")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown asset = %d, want 404", resp.StatusCode)
	}
}

// A browser cannot put an Authorization header on a document or script load, so
// the UI shell has to be reachable without the token while /api stays gated.
func TestTokenGuardsAPIButNotDashboard(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	srv := httptest.NewServer(NewRouter(h.svc, RouterOptions{
		Token: "s3cret", Logger: quietLogger()}))
	defer srv.Close()

	for _, path := range []string{"/", "/app.js", "/style.css"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with auth enabled = %d, want 200", path, resp.StatusCode)
		}
	}

	resp, err := srv.Client().Get(srv.URL + "/api/status")
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/status without token = %d, want 401", resp.StatusCode)
	}
}

func TestStaticRejectsWrites(t *testing.T) {
	h := newHarness(t, testNodes(), nil)

	resp, err := h.srv.Client().Post(h.srv.URL+"/", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST / = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
	}
}
