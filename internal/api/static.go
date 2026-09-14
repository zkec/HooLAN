package api

// Static assets for the dashboard, compiled into the binary.
//
// Embedding rather than shipping a directory is deliberate: this runs as a
// systemd unit on a Debian host and is deployed by copying one file. A separate web root
// would be one more path to get wrong in the unit file, and a missing asset
// directory would leave an operator with a working API and a blank page.
//
// Login assets are public. Dashboard documents redirect unauthenticated
// browsers to login when a token is configured; privileged APIs enforce their
// own authentication and CSRF checks independently of the embedded shell.

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// webFS holds the dashboard. The pattern excludes dotfiles by default, which is
// what we want: editor swap files must not end up in the binary.
//
//go:embed web
var webFS embed.FS

// asset is one precomputed file. Content type and ETag are resolved once at
// startup instead of per request: the bytes cannot change at runtime, and this
// keeps the hot path a map lookup on a Debian host's modest CPU.
type asset struct {
	body        []byte
	contentType string
	etag        string
}

// assets maps a request path ("/app.js") to its file. Built once; see initErr.
var (
	assets  map[string]asset
	initErr error
)

func init() {
	assets, initErr = loadAssets()
}

func loadAssets() (map[string]asset, error) {
	out := make(map[string]asset)
	err := fs.WalkDir(webFS, "web", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		body, err := webFS.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		sum := sha256.Sum256(body)
		out["/"+strings.TrimPrefix(p, "web/")] = asset{
			body:        body,
			contentType: contentTypeFor(p),
			// Weak-free strong ETag over the content: with a zero modtime there
			// is no Last-Modified to validate against, so this is the only way a
			// reload gets a 304 instead of refetching the whole page.
			etag: `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := out["/index.html"]; !ok {
		return nil, fmt.Errorf("api: embedded web assets missing index.html")
	}
	return out, nil
}

// contentTypeFor names types explicitly rather than trusting mime.TypeByExtension,
// which reads /etc/mime.types and has been known to return text/plain for .js on
// a minimal image -- which browsers refuse to execute.
func contentTypeFor(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".json":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".png":
		return "image/png"
	case ".woff2":
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}

// staticHandler serves the embedded dashboard at the site root.
func (h *handlers) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Anything under /api that reached the root handler is an unknown API
		// route. Answering with index.html would hand a JSON client a page of
		// HTML under a 200; a 404 in the shape it expects is far easier to debug.
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" {
			writeError(w, http.StatusNotFound, "no such API route: "+r.URL.Path)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed,
				fmt.Sprintf("method %s not allowed; use GET", r.Method))
			return
		}
		if initErr != nil {
			// A build-time problem, but the API must still serve: an operator
			// needs curl to work so they can turn interception off.
			h.log.Error("embedded web assets unavailable", "err", initErr)
			writeError(w, http.StatusInternalServerError,
				"dashboard assets unavailable; the API is still usable via /api")
			return
		}

		name := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		if name == "/login" || name == "/login/" {
			name = "/login.html"
		}
		if (name == "/" || name == "/index.html") && h.opts.Token != "" && h.requestSession(r) == nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}
		if name == "/" {
			name = "/index.html"
		}
		a, ok := assets[name]
		if !ok {
			// No SPA catch-all rewrite: this dashboard is one page with no
			// client-side router, so an unknown path is a genuine 404 rather
			// than a deep link.
			writeError(w, http.StatusNotFound, "not found: "+r.URL.Path)
			return
		}

		hdr := w.Header()
		hdr.Set("ETag", a.etag)
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("X-Frame-Options", "DENY")
		if strings.HasSuffix(name, ".html") {
			// Revalidate the entry point every load so a binary upgrade is
			// picked up without a hard refresh; the ETag keeps that cheap.
			hdr.Set("Cache-Control", "no-cache")
			// All dashboard/login scripts and styles are embedded locally.
			hdr.Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js; "+
					"style-src 'self'; img-src 'self' data:; "+
					"connect-src 'self'; font-src 'self' data:; "+
					"object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "+
					"form-action 'self'")
		} else {
			hdr.Set("Cache-Control", "no-cache")
		}
		hdr.Set("Content-Type", a.contentType)

		// ServeContent handles conditional requests, HEAD and ranges. The zero
		// modtime suppresses Last-Modified, leaving the ETag as the validator --
		// embedded files have no meaningful mtime.
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(a.body))
	})
}
