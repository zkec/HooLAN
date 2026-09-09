package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"proxy-manager/internal/logstream"
)

func (h *handlers) logs(w http.ResponseWriter, r *http.Request) {
	if h.opts.Logs == nil {
		writeError(w, http.StatusServiceUnavailable, "live logs unavailable")
		return
	}
	var after uint64
	if raw := r.Header.Get("Last-Event-ID"); raw != "" {
		var err error
		after, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid Last-Event-ID")
			return
		}
	}
	history, events, cancel, err := h.opts.Logs.Subscribe(after)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	defer cancel()

	controller := http.NewResponseController(w)
	// Override only this request's ordinary HTTP WriteTimeout. Each individual
	// event write below still has a deadline so slow readers release resources.
	if err := controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeError(w, http.StatusInternalServerError, "streaming deadline unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")

	var revoked <-chan struct{}
	var expired <-chan time.Time
	if session, ok := r.Context().Value(sessionContextKey{}).(*browserSession); ok {
		revoked = session.done
		timer := time.NewTimer(time.Until(session.expires))
		defer timer.Stop()
		expired = timer.C
	}
	active := func() bool {
		select {
		case <-r.Context().Done():
			return false
		case <-revoked:
			return false
		case <-expired:
			return false
		default:
			return true
		}
	}
	write := func(frame string) bool {
		if !active() {
			return false
		}
		_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprint(w, frame); err != nil {
			return false
		}
		if err := controller.Flush(); err != nil {
			return false
		}
		_ = controller.SetWriteDeadline(time.Time{})
		return true
	}
	writeEntry := func(entry logstream.Entry) bool {
		data, err := json.Marshal(entry)
		if err != nil {
			return false
		}
		return write(fmt.Sprintf("id: %d\nevent: log\ndata: %s\n\n", entry.ID, data))
	}
	if !write(": connected\nretry: 3000\n\n") {
		return
	}
	for _, entry := range history {
		if !writeEntry(entry) {
			return
		}
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-revoked:
			return
		case <-expired:
			return
		case <-heartbeat.C:
			if !write(": heartbeat\n\n") {
				return
			}
		case entry, ok := <-events:
			if !ok || !writeEntry(entry) {
				return
			}
		}
	}
}
