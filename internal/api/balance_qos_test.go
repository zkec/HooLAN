package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"hoolan/internal/engine"
	"hoolan/internal/netfilter"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"reflect"
	"testing"
)

type distributionTestFirewall struct {
	*fakeFirewall
	groups             []engine.DistributionGroup
	selected           string
	routes             map[string]string
	desired, installed map[string]netfilter.DeviceLimits
	syncs              int
	failNext           bool
}

func (f *distributionTestFirewall) ConfigureDistribution(g []engine.DistributionGroup, id string, r map[string]string) {
	f.groups = g
	f.selected = id
	f.routes = copyStrings(r)
}
func (f *distributionTestFirewall) ConfigureDeviceLimits(l map[string]netfilter.DeviceLimits) {
	f.desired = cloneLimits(l)
}
func (f *distributionTestFirewall) ApplyDeviceLimits(_ context.Context, l map[string]netfilter.DeviceLimits) error {
	f.syncs++
	if f.failNext {
		f.failNext = false
		return errors.New("nft rejected batch")
	}
	f.installed = cloneLimits(l)
	return nil
}
func balanceHarness(t *testing.T) (*harness, *distributionTestFirewall) {
	var fw *distributionTestFirewall
	h := newLocalHarness(t, testNodes(), func(c *Config) {
		fw = &distributionTestFirewall{fakeFirewall: c.Firewall.(*fakeFirewall)}
		c.Firewall = fw
		c.Engine = &deviceEngine{fakeEngine: c.Engine.(*fakeEngine)}
	})
	return h, fw
}
func floatptr(v float64) *float64 { return &v }
func TestDeviceLimitsPersistApplyRollbackAndRestoreWhileOff(t *testing.T) {
	h, fw := balanceHarness(t)
	ctx := context.Background()
	ip := "192.168.3.141"
	id := h.store.All()[0].ID
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: ip, Alias: strptr("Phone"), NodeID: &id, SpeedLimit: floatptr(8.5)}); err != nil {
		t.Fatal(err)
	}
	persisted, err := h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.DeviceLimits[ip] != netfilter.UniformLimits(8.5) || persisted.DeviceAliases[ip] != "Phone" || persisted.DeviceRoutes[ip] != id || fw.installed[ip] != netfilter.UniformLimits(8.5) {
		t.Fatal("combined device settings not applied/persisted")
	}
	fw.failNext = true
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: ip, Alias: strptr("Changed"), SpeedLimit: floatptr(12)}); err == nil {
		t.Fatal("nft failure accepted")
	}
	persisted, _ = h.svc.loadState()
	if persisted.DeviceLimits[ip] != netfilter.UniformLimits(8.5) || persisted.DeviceAliases[ip] != "Phone" || fw.installed[ip] != netfilter.UniformLimits(8.5) {
		t.Fatal("nft failure did not restore previous settings")
	}
	before := fw.syncs
	oldPath := h.svc.cfg.StatePath
	h.svc.cfg.StatePath = filepath.Join(oldPath, "invalid")
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: ip, SpeedLimit: floatptr(20)}); err == nil {
		t.Fatal("state write failure accepted")
	}
	h.svc.cfg.StatePath = oldPath
	if fw.syncs != before || h.svc.state.DeviceLimits[ip] != netfilter.UniformLimits(8.5) {
		t.Fatal("write failure changed kernel or memory")
	}
	fw.installed = nil
	if err := h.svc.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if fw.installed[ip] != netfilter.UniformLimits(8.5) {
		t.Fatal("OFF startup failed to restore QoS")
	}
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: ip, SpeedLimit: floatptr(0)}); err != nil {
		t.Fatal(err)
	}
	if len(fw.installed) != 0 || len(h.svc.state.DeviceLimits) != 0 || h.svc.state.DeviceAliases[ip] != "Phone" {
		t.Fatal("zero did not clear only limit")
	}
}
func TestLoadBalancerSnapshotsChainsPrunesAndDeletes(t *testing.T) {
	h, fw := balanceHarness(t)
	ctx := context.Background()
	originals := h.store.All()
	chain, err := h.svc.CreateChain(ctx, "Original chain", []string{originals[0].ID, originals[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	id, err := h.svc.CreateLoadBalancer(ctx, "Balanced", []string{chain, originals[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	root, err := h.store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if root.Node.Protocol != subscription.ProtoBalance || len(root.Node.BalanceMembers) != 2 || !h.svc.state.ManualNodeIDs[id] {
		t.Fatal("group not saved as manual configuration")
	}
	if len(fw.groups) != 1 || len(fw.groups[0].Members) != 2 {
		t.Fatal("listener plan missing")
	}
	// Neither a nested group nor duplicates may mutate the store.
	count := h.store.Len()
	for _, ids := range [][]string{{id, originals[0].ID}, {originals[0].ID, originals[0].ID}} {
		if _, err := h.svc.CreateLoadBalancer(ctx, "invalid", ids); err == nil || h.store.Len() != count {
			t.Fatal("invalid group persisted")
		}
	}
	if _, err := h.svc.Select(ctx, false, id); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: "192.168.3.141", NodeID: &id}); err != nil {
		t.Fatal(err)
	}
	if fw.selected != id || fw.routes["192.168.3.141"] != id {
		t.Fatal("global/device group intent missing")
	}
	if _, err := h.svc.DeleteNodes(ctx, []string{chain, originals[0].ID, originals[1].ID}); err != nil {
		t.Fatal(err)
	}
	nodes := h.store.EnabledNodes()
	if err := subscription.ValidateChains(nodes); err != nil {
		t.Fatal(err)
	}
	plan, err := engine.DistributionPlan(nodes, 7892)
	if err != nil || len(plan) != 1 {
		t.Fatalf("source deletion broke copied group: %v", err)
	}
	private := 0
	for _, n := range nodes {
		if n.ChainInternal {
			private++
		}
	}
	if private != 3 {
		t.Fatalf("chain snapshots missing: %d", private)
	}
	if _, err := h.svc.DeleteNodes(ctx, []string{id}); err != nil {
		t.Fatal(err)
	}
	if h.store.Len() != 0 || len(h.svc.state.DeviceRoutes) != 0 || !h.svc.state.AutoSelect {
		t.Fatal("group deletion left copies or routes")
	}
}
func TestLoadBalancerIdentityAndSelectionRollback(t *testing.T) {
	h, fw := balanceHarness(t)
	ctx := context.Background()
	originals := h.store.All()
	id, err := h.svc.CreateLoadBalancer(ctx, "Balanced", []string{originals[0].ID, originals[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := h.store.Get(id)
	if store.NodeID(root.Node) != id {
		t.Fatal("unstable group identity")
	}
	snapshot := h.store.All()
	badPath := h.svc.cfg.StatePath
	h.svc.cfg.StatePath = filepath.Join(badPath, "invalid")
	if _, err := h.svc.CreateLoadBalancer(ctx, "write failure", []string{originals[0].ID, originals[1].ID}); err == nil {
		t.Fatal("write error hidden")
	}
	h.svc.cfg.StatePath = badPath
	if !reflect.DeepEqual(snapshot, h.store.All()) {
		t.Fatal("failed creation changed inventory")
	}
	// Activate against a fake running engine without binding host sockets.
	h.svc.state.AutoSelect = false
	h.svc.state.SelectedNodeID = originals[0].ID
	h.eng.running = true
	h.svc.tagByID = map[string]string{originals[0].ID: originals[0].Node.Tag, id: "Balanced"}
	fw.fakeFirewall.applyErr = errors.New("atomic apply rejected")
	if _, err := h.svc.Select(ctx, false, id); err == nil {
		t.Fatal("failed firewall apply accepted")
	}
	if h.svc.state.SelectedNodeID != originals[0].ID || fw.selected != originals[0].ID {
		t.Fatal("selection not rolled back")
	}
	h.eng.running = false
}

type balanceBackupFirewall struct {
	*distributionTestFirewall
	path string
}

func (f *balanceBackupFirewall) ConfigPath() string { return f.path }

type balanceBackupEngine struct{ *deviceEngine }

func (e *balanceBackupEngine) TProxyPort() int { return 7892 }
func TestLoadBalancerAndLimitsBackupRoundTrip(t *testing.T) {
	h, fw := balanceHarness(t)
	ctx := context.Background()
	conf := filepath.Join(h.dir, "tproxy.conf")
	if err := os.WriteFile(conf, []byte(backupConf), 0600); err != nil {
		t.Fatal(err)
	}
	h.svc.cfg.Firewall = &balanceBackupFirewall{fw, conf}
	h.svc.cfg.Engine = &balanceBackupEngine{h.svc.cfg.Engine.(*deviceEngine)}
	originals := h.store.All()
	id, err := h.svc.CreateLoadBalancer(ctx, "Backup balance", []string{originals[0].ID, originals[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: "192.168.3.141", NodeID: &id, SpeedLimit: floatptr(5)}); err != nil {
		t.Fatal(err)
	}
	raw, err := h.svc.makeBackup()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := decodeBackup(raw, 7892)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.DeleteNodes(ctx, []string{id}); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.applyBackup(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Get(id); err != nil || h.svc.state.DeviceRoutes["192.168.3.141"] != id || fw.installed["192.168.3.141"] != netfilter.UniformLimits(5) {
		t.Fatal("restore lost balancer, device mapping or applied rate")
	}
	// A corrupted group reference must be rejected before any restore mutation.
	bad := rewriteZIP(t, raw, func(name string, b []byte) (string, []byte) {
		if name != "nodes.json" {
			return name, b
		}
		var n backupNodes
		if err := json.Unmarshal(b, &n); err != nil {
			t.Fatal(err)
		}
		for i := range n.Records {
			if n.Records[i].ID == id {
				n.Records[i].Node.BalanceMembers[0] = "missing"
			}
		}
		b, _ = json.Marshal(n)
		return name, b
	})
	if _, err := decodeBackup(bad, 7892); err == nil {
		t.Fatal("missing group member accepted")
	}
}

func TestLoadBalancerStrategyPersists(t *testing.T) {
	h, fw := balanceHarness(t)
	all := h.store.All()
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	raw, _ := json.Marshal(map[string]any{"name": "Latency group", "node_ids": []string{all[0].ID, all[1].ID}, "strategy": "latency"})
	response := authRequest(router, "POST", "/api/load-balancers", string(raw), nil, "")
	if response.Code != 201 {
		t.Fatal(response.Body.String())
	}
	var result map[string]string
	json.Unmarshal(response.Body.Bytes(), &result)
	rec, err := h.store.Get(result["node_id"])
	if err != nil || rec.Node.BalanceStrategy != "latency" {
		t.Fatalf("strategy lost: %v", err)
	}
	if len(fw.groups) != 0 {
		t.Fatal("latency group incorrectly installed hash dispatcher")
	}
	if _, err := h.svc.CreateLoadBalancerWithStrategy(context.Background(), "invalid", []string{all[0].ID, all[1].ID}, "least-load"); err == nil {
		t.Fatal("unsupported strategy accepted")
	}
}
