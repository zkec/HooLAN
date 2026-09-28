package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Same server and credential, with six distinct security/SNI/service variants.
// Use synthetic credentials and hosts rather than a real subscription's secrets.
func sixManualLinks() string {
	var links []string
	for i := 0; i < 6; i++ {
		links = append(links, fmt.Sprintf("vless://00000000-0000-0000-0000-000000000001@192.0.2.1:443/?security=tls&sni=site%d.example&type=grpc&serviceName=service%d&encryption=none#grpc%%20vless%%20%d%%20", i%2, i/2, i))
	}
	return strings.Join(links, " ")
}

func TestManualBatchImportHTTP(t *testing.T) {
	h := newLocalHarness(t, nil, nil)
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	body, _ := json.Marshal(map[string]string{"link": sixManualLinks()})
	w := authRequest(router, "POST", "/api/nodes", string(body), nil, "")
	if w.Code != 201 {
		t.Fatalf("import=%d %s", w.Code, w.Body.String())
	}
	var result struct {
		ID    string   `json:"node_id"`
		IDs   []string `json:"node_ids"`
		Count int      `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Count != 6 || len(result.IDs) != 6 || result.ID != result.IDs[0] || h.store.Len() != 6 {
		t.Fatalf("result=%+v, inventory=%d", result, h.store.Len())
	}
	for _, id := range result.IDs {
		if !h.svc.state.ManualNodeIDs[id] {
			t.Fatal("missing manual ownership")
		}
		r, err := h.store.Get(id)
		if err != nil || strings.Contains(r.Node.Tag, "://") {
			t.Fatal("links merged into name")
		}
	}
	ids, err := h.svc.AddManualNodes(context.Background(), sixManualLinks()+" "+sixManualLinks())
	if err != nil || len(ids) != 6 || h.store.Len() != 6 {
		t.Fatalf("duplicate import: %v %v", ids, err)
	}
}

func TestManualBatchValidationAndRollback(t *testing.T) {
	h := newLocalHarness(t, nil, nil)
	ctx := context.Background()
	for _, paste := range []string{"", sixManualLinks() + "\ninvalid", sixManualLinks() + " unsupported://bad", strings.Repeat("x", 65537)} {
		if _, err := h.svc.AddManualNodes(ctx, paste); err == nil {
			t.Fatal("invalid paste accepted")
		}
		if h.store.Len() != 0 || len(h.svc.state.ManualNodeIDs) != 0 {
			t.Fatal("partial import")
		}
	}
	id, err := h.svc.AddManualNode(ctx, providerLink)
	if err != nil {
		t.Fatal(err)
	}
	h.svc.cfg.StatePath = t.TempDir()
	if _, err := h.svc.AddManualNodes(ctx, sixManualLinks()); err == nil {
		t.Fatal("expected save failure")
	}
	if h.store.Len() != 1 || len(h.svc.state.ManualNodeIDs) != 1 || !h.svc.state.ManualNodeIDs[id] {
		t.Fatal("failed import did not roll back")
	}
}
