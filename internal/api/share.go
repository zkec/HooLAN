package api

import (
	"net/http"
	"proxy-manager/internal/subscription"
)

func (h *handlers) shareNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"node_id"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	rec, err := h.svc.cfg.Store.Get(req.ID)
	if err != nil {
		h.dashboardError(w, err)
		return
	}
	if rec.ChainID != "" || rec.DetourID != "" {
		writeError(w, 400, "Chains cannot be exported as a single mobile link")
		return
	}
	link, err := subscription.ShareLink(rec.Node)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"link": link})
}
