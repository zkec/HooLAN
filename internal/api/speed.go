package api

import (
	"context"
	"fmt"
	"net/http"
	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
	"proxy-manager/internal/tester"
	"time"
)

func (h *handlers) speedTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"node_id"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	speed, ok := h.svc.cfg.Tester.(interface {
		TestSpeed(context.Context, subscription.Node, []subscription.Node) (tester.SpeedResult, error)
	})
	if !ok {
		writeError(w, 503, "Speed testing is unavailable")
		return
	}
	rec, err := h.svc.cfg.Store.Get(req.ID)
	if err != nil {
		h.dashboardError(w, err)
		return
	}
	if !rec.Enabled || rec.Node.ChainInternal || rec.Node.Protocol == subscription.ProtoBalance {
		writeError(w, 400, "Choose an enabled configuration")
		return
	}
	job, err := h.svc.startJob(JobStatus{Kind: "speed", NodeID: req.ID}, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		// Inventory mutations reject an active job. Capture post-deduplication tags.
		all := h.svc.cfg.Store.EnabledNodes()
		var target *subscription.Node
		for i := range all {
			if store.NodeID(all[i]) == req.ID {
				target = &all[i]
				break
			}
		}
		if target == nil {
			return fmt.Errorf("configuration is no longer enabled")
		}
		result, err := speed.TestSpeed(ctx, *target, all)
		if err != nil {
			return err
		}
		h.svc.mu.Lock()
		h.svc.job.Speed = &result
		h.svc.mu.Unlock()
		return nil
	})
	h.writeJob(w, job, err)
}
