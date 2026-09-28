package api

import (
	"errors"
	"hoolan/internal/engine"
	"net/http"

	"hoolan/internal/store"
)

func (h *handlers) registerDashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/telegram", h.svc.telegram)
	mux.Handle("/api/telegram/test", only(http.MethodPost, h.testTelegram))
	mux.Handle("/api/backup", only(http.MethodGet, h.backup))
	mux.Handle("/api/restore", only(http.MethodPost, h.restoreBackup))
	mux.Handle("/api/nodes/speed", only(http.MethodPost, h.speedTest))
	mux.Handle("/api/nodes/share", only(http.MethodPost, h.shareNode))
	mux.Handle("/api/load-balancers", only(http.MethodPost, h.createLoadBalancer))
	mux.HandleFunc("/api/chains", h.chains)
	mux.HandleFunc("/api/nodes/edit", h.editNode)
	mux.Handle("/api/nodes/delete", only(http.MethodPost, h.deleteNode))
	mux.Handle("/api/nodes/detour", only(http.MethodPut, h.detourNode))
	mux.Handle("/api/devices", only(http.MethodPut, h.updateDevice))
	mux.Handle("/api/usage", only(http.MethodGet, h.usage))
	mux.HandleFunc("/api/rules", h.rules)
	mux.Handle("/api/rules/update", only(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		job, err := h.svc.StartRuleUpdate()
		h.writeJob(w, job, err)
	}))
	mux.HandleFunc("/api/subscriptions", h.subscriptions)
	mux.Handle("/api/subscriptions/refresh", only(http.MethodPost, h.refreshSubscription))
	mux.Handle("/api/subscriptions/test", only(http.MethodPost, h.testSubscription))
	mux.Handle("/api/nodes/test", only(http.MethodPost, h.testNode))
	mux.HandleFunc("/api/settings", h.settings)
}

func (h *handlers) nodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listNodes(w, r)
	case http.MethodPost:
		var req struct {
			Link string `json:"link"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ids, err := h.svc.AddManualNodes(r.Context(), req.Link)
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"node_id": ids[0], "node_ids": ids, "count": len(ids), "message": "Manual configs saved"})

	default:
		methodsNotAllowed(w, "GET, POST")
	}
}

func (h *handlers) subscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"subscriptions": h.svc.Subscriptions()})
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		sub, err := h.svc.AddSubscription(req.Name, req.URL)
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, sub)
	case http.MethodDelete:
		var req struct {
			ID string `json:"subscription_id"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		removed, err := h.svc.RemoveSubscription(r.Context(), req.ID)
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"removed_nodes": removed})
	default:
		methodsNotAllowed(w, "GET, POST, DELETE")
	}
}

func (h *handlers) refreshSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"subscription_id"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	job, err := h.svc.StartSubscriptionRefresh(req.ID)
	h.writeJob(w, job, err)
}

func (h *handlers) testSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"subscription_id"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	job, err := h.svc.StartLatencyTest("", req.ID)
	h.writeJob(w, job, err)
}

func (h *handlers) testNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"node_ids"`
		ID  string   `json:"node_id"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.ID != "" {
		if len(req.IDs) > 0 {
			writeError(w, 400, "use node_ids or node_id, not both")
			return
		}
		req.IDs = []string{req.ID}
	}
	job, err := h.svc.StartBulkLatency(req.IDs)
	h.writeJob(w, job, err)
}

func (h *handlers) settings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, h.svc.Settings())
	case http.MethodPut:
		var req struct {
			FakeDNS     *engine.FakeDNSOptions `json:"fake_dns"`
			TunneledDoH *string                `json:"tunneled_doh"`
			DirectDNS   *string                `json:"direct_dns"`
			DNSServer   *string                `json:"dns_server"`
			IranBypass  *bool                  `json:"iran_bypass"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.TunneledDoH == nil && req.DirectDNS == nil && req.DNSServer == nil && req.IranBypass == nil && req.FakeDNS == nil {
			writeError(w, http.StatusBadRequest, "provide tunneled_doh, direct_dns, iran_bypass or fake_dns")
			return
		}
		settings := h.svc.Settings()
		if req.FakeDNS != nil {
			settings.FakeDNS = *req.FakeDNS
		}
		if req.DNSServer != nil {
			settings.DNSServer = *req.DNSServer
			settings.DirectDNS = *req.DNSServer
		}
		if req.TunneledDoH != nil {
			settings.TunneledDoH = *req.TunneledDoH
		}
		if req.DirectDNS != nil {
			settings.DirectDNS = *req.DirectDNS
		}
		if req.IranBypass != nil {
			settings.IranBypass = *req.IranBypass
		}
		settings, err := h.svc.UpdateSettings(r.Context(), settings)
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, settings)
	default:
		methodsNotAllowed(w, "GET, PUT")
	}
}

func (h *handlers) writeJob(w http.ResponseWriter, job JobStatus, err error) {
	if errors.Is(err, ErrRefreshInProgress) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another refresh or latency test is running", "refresh": job})
		return
	}
	if err != nil {
		h.dashboardError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started", "refresh": job, "poll": "/api/status"})
}

func (h *handlers) dashboardError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrInvalidInput):
		status = http.StatusBadRequest
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrNoTester), errors.Is(err, ErrNoSubscriptions):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ErrNoNodes), errors.Is(err, ErrRefreshInProgress):
		status = http.StatusConflict
	}
	writeError(w, status, err.Error())
}

func methodsNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed; use "+allow)
}
