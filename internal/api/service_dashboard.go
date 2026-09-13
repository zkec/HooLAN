package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"proxy-manager/internal/engine"
	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
	"proxy-manager/internal/tester"
)

// Subscription retains source membership separately from the deduplicated node
// store. A node can belong to several providers and also be added manually.
type Subscription struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	NodeIDs []string `json:"node_ids,omitempty"`
}

type SubscriptionView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	NodeCount int    `json:"node_count"`
}

type Settings struct {
	DNSServer  string `json:"dns_server"`
	IranBypass bool   `json:"iran_bypass"`
}

var ErrInvalidInput = errors.New("api: invalid input")
var ErrNoTester = errors.New("api: no latency tester configured")

func sourceID(raw string) string { return fmt.Sprintf("sub-%x", sha256.Sum256([]byte(raw)))[:28] }

func (s *Service) seedSubscriptions() {
	if s.state.ManualNodeIDs == nil {
		s.state.ManualNodeIDs = make(map[string]bool)
	}
	seen := make(map[string]bool)
	for _, sub := range s.state.Subscriptions {
		seen[sub.URL] = true
	}
	for _, raw := range s.cfg.SubscriptionURLs {
		if seen[raw] {
			continue
		}
		name := filepath.Base(raw)
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			name = u.Hostname()
		}
		s.state.Subscriptions = append(s.state.Subscriptions, Subscription{ID: sourceID(raw), Name: name, URL: raw})
		seen[raw] = true
	}
}

func (s *Service) subscriptionSnapshot() []Subscription {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Subscription(nil), s.state.Subscriptions...)
	for i := range out {
		out[i].NodeIDs = append([]string(nil), out[i].NodeIDs...)
	}
	return out
}

func (s *Service) Subscriptions() []SubscriptionView {
	result := make([]SubscriptionView, 0)
	for _, sub := range s.subscriptionSnapshot() {
		count := 0
		for _, id := range sub.NodeIDs {
			if _, err := s.cfg.Store.Get(id); err == nil {
				count++
			}
		}
		result = append(result, SubscriptionView{ID: sub.ID, Name: sub.Name, URL: sub.URL, NodeCount: count})
	}
	return result
}

func (s *Service) AddSubscription(name, raw string) (SubscriptionView, error) {
	raw, name = strings.TrimSpace(raw), strings.TrimSpace(name)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.Fragment != "" || len(raw) > 8192 {
		return SubscriptionView{}, fmt.Errorf("%w: subscription must be an HTTP or HTTPS URL without a fragment", ErrInvalidInput)
	}
	if len(name) > 160 {
		return SubscriptionView{}, fmt.Errorf("%w: name is too long", ErrInvalidInput)
	}
	if name == "" {
		name = u.Hostname()
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return SubscriptionView{}, errors.New("api: shutting down")
	}
	for _, sub := range s.state.Subscriptions {
		if sub.URL == raw {
			return SubscriptionView{ID: sub.ID, Name: sub.Name, URL: sub.URL, NodeCount: len(sub.NodeIDs)}, nil
		}
	}
	if len(s.state.Subscriptions) >= 128 {
		return SubscriptionView{}, fmt.Errorf("%w: subscription limit reached", ErrInvalidInput)
	}
	sub := Subscription{ID: sourceID(raw), Name: name, URL: raw}
	previous := s.state.Subscriptions
	s.state.Subscriptions = append(append([]Subscription(nil), previous...), sub)
	if err := s.saveState(); err != nil {
		s.state.Subscriptions = previous
		return SubscriptionView{}, err
	}
	return SubscriptionView{ID: sub.ID, Name: sub.Name, URL: sub.URL}, nil
}

func (s *Service) NodeOrigins(id string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0)
	for _, sub := range s.state.Subscriptions {
		for _, node := range sub.NodeIDs {
			if node == id {
				ids = append(ids, sub.ID)
				break
			}
		}
	}
	// Legacy stores have no source metadata. Keep those nodes visible until a
	// refresh associates them with a subscription.
	return ids, s.state.ManualNodeIDs[id] || len(ids) == 0
}

func (s *Service) AddManualNode(ctx context.Context, link string) (string, error) {
	link = strings.TrimSpace(link)
	if len(link) > 64<<10 || strings.ContainsAny(link, "\r\n") {
		return "", fmt.Errorf("%w: provide one node link", ErrInvalidInput)
	}
	node, err := subscription.ParseLink(link)
	if err != nil {
		return "", fmt.Errorf("%w: node link is invalid or unsupported", ErrInvalidInput)
	}
	if err := node.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	id := store.NodeID(node)
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return "", errors.New("api: shutting down")
	}
	previous := s.state.ManualNodeIDs[id]
	s.state.ManualNodeIDs[id] = true
	if err := s.saveState(); err != nil {
		if !previous {
			delete(s.state.ManualNodeIDs, id)
		}
		s.mu.Unlock()
		return "", err
	}
	s.mu.Unlock()
	if _, _, err := s.cfg.Store.UpsertNodes([]subscription.Node{node}); err != nil {
		return "", err
	}
	if err := s.reloadRunningLocked(ctx); err != nil {
		return id, fmt.Errorf("node saved; applying it failed: %w", err)
	}
	return id, nil
}

func (s *Service) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings := Settings{DNSServer: s.state.DNSServer, IranBypass: true}
	if s.state.IranBypass != nil {
		settings.IranBypass = *s.state.IranBypass
	}
	return settings
}

func (s *Service) configureEngineRouting() error {
	if err := s.configureDistribution(); err != nil {
		return err
	}
	if err := s.configureDeviceLimits(); err != nil {
		return err
	}
	if err := s.configureRulePolicy(); err != nil {
		return err
	}
	if configurable, ok := s.cfg.Engine.(interface{ ConfigureAutoSelection(bool) }); ok {
		s.mu.RLock()
		auto := s.state.AutoSelect
		s.mu.RUnlock()
		configurable.ConfigureAutoSelection(auto)
	}
	if configurable, ok := s.cfg.Engine.(interface{ ConfigureDeviceRoutes(map[string]string) }); ok {
		s.mu.RLock()
		routes := copyStrings(s.state.DeviceRoutes)
		s.mu.RUnlock()
		configurable.ConfigureDeviceRoutes(routes)
	}
	settings := s.Settings()
	if configurable, ok := s.cfg.Engine.(interface{ ConfigureRouting(string, bool) error }); ok {
		return configurable.ConfigureRouting(settings.DNSServer, settings.IranBypass)
	}
	return nil
}

func (s *Service) UpdateSettings(ctx context.Context, settings Settings) (Settings, error) {
	value, err := engine.NormalizeDNSServer(settings.DNSServer)
	if err != nil {
		return Settings{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	settings.DNSServer = value
	s.opMu.Lock()
	defer s.opMu.Unlock()
	previous := s.Settings()
	if previous == settings {
		return settings, nil
	}
	if _, ok := s.cfg.Engine.(interface{ ConfigureRouting(string, bool) error }); !ok {
		return previous, errors.New("engine does not support routing settings")
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return previous, errors.New("api: shutting down")
	}
	oldDNS, oldIran := s.state.DNSServer, s.state.IranBypass
	s.state.DNSServer, s.state.IranBypass = settings.DNSServer, &settings.IranBypass
	if err := s.saveState(); err != nil {
		s.state.DNSServer, s.state.IranBypass = oldDNS, oldIran
		s.mu.Unlock()
		return previous, err
	}
	s.mu.Unlock()
	err = s.configureEngineRouting()
	if err == nil {
		err = s.reloadRunningLocked(ctx)
	}
	if err != nil {
		s.mu.Lock()
		s.state.DNSServer, s.state.IranBypass = oldDNS, oldIran
		saveErr := s.saveState()
		s.mu.Unlock()
		configureErr := s.configureEngineRouting()
		return previous, errors.Join(fmt.Errorf("settings were not applied: %w", err), saveErr, configureErr)
	}
	return settings, nil
}

// reloadRunningLocked removes interception before a deliberate restart. A
// failed start/check leaves the gateway un-intercepted, never pointing into an
// empty listener. Caller owns opMu; network fetches/probes do not hold it.
func (s *Service) reloadRunningLocked(ctx context.Context) error {
	s.mu.RLock()
	enabled := s.proxyEnabled
	s.mu.RUnlock()
	if !enabled && !s.cfg.Engine.Running() {
		return nil
	}
	if err := s.cfg.Firewall.Remove(ctx); err != nil {
		return fmt.Errorf("remove interception before reload: %w", err)
	}
	s.mu.Lock()
	s.proxyEnabled = false
	s.mu.Unlock()
	nodes := s.cfg.Store.EnabledNodes()
	if len(nodes) == 0 {
		s.cleanupFailedEnable()
		return ErrNoNodes
	}
	if err := s.applyEngine(ctx, nodes); err != nil {
		s.cleanupFailedEnable()
		return err
	}
	if err := s.waitEngineListening(ctx); err != nil {
		s.cleanupFailedEnable()
		return err
	}
	if err := s.applySelection(ctx); err != nil {
		s.warn(fmt.Sprintf("reapply selection after reload: %v", err))
	}
	if enabled {
		if v, ok := s.cfg.Firewall.(interface{ ValidatePort(int) error }); ok {
			if err := v.ValidatePort(s.cfg.Engine.TProxyPort()); err != nil {
				s.cleanupFailedEnable()
				return err
			}
		}
		if err := s.cfg.Firewall.Apply(ctx); err != nil {
			s.cleanupFailedEnable()
			return err
		}
		s.mu.Lock()
		s.proxyEnabled = true
		s.mu.Unlock()
		if !s.cfg.Engine.Running() {
			s.cleanupFailedEnable()
			return errors.New("sing-box exited while installing interception")
		}
	}
	s.notify("Proxy engine stopped and restarted to apply configuration changes.")
	return nil
}

func (s *Service) cleanupFailedEnable() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.cfg.Firewall.Remove(ctx); err != nil {
		s.log.Error("could not remove interception after failed startup", "err", err)
		return // keep any surviving engine serving if firewall removal failed
	}
	s.mu.Lock()
	s.proxyEnabled = false
	s.mu.Unlock()
	s.setIntentionalStop(true)
	defer s.setIntentionalStop(false)
	if err := s.cfg.Engine.Stop(ctx); err != nil {
		s.log.Error("stop after failed startup", "err", err)
	}
}

func (s *Service) startJob(initial JobStatus, work func(context.Context) error) (JobStatus, error) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return JobStatus{}, errors.New("api: shutting down")
	}
	if s.refreshing {
		j := s.job
		s.mu.Unlock()
		return j, ErrRefreshInProgress
	}
	s.refreshing = true
	initial.ID = fmt.Sprintf("%s-%d", initial.Kind, time.Now().UnixNano())
	initial.State, initial.StartedAt = "running", time.Now()
	s.job = initial
	s.jobs.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.jobs.Done()
		ctx, cancel := context.WithTimeout(s.jobCtx, s.cfg.RefreshTimeout)
		defer cancel()
		err := work(ctx)
		s.mu.Lock()
		s.refreshing = false
		s.job.FinishedAt = time.Now()
		s.job.State = "succeeded"
		if err != nil {
			s.job.State, s.job.Error = "failed", err.Error()
		}
		s.mu.Unlock()
		if err != nil {
			s.log.Error("background job failed", "kind", initial.Kind, "err", err)
		}
	}()
	return initial, nil
}

func (s *Service) StartSubscriptionRefresh(id string) (JobStatus, error) {
	for _, sub := range s.subscriptionSnapshot() {
		if sub.ID == id {
			return s.startJob(JobStatus{Kind: "refresh", SubscriptionID: id, SourcesTotal: 1}, func(ctx context.Context) error { return s.refreshSources(ctx, []Subscription{sub}, true) })
		}
	}
	return JobStatus{}, store.ErrNotFound
}

func (s *Service) refreshSources(ctx context.Context, sources []Subscription, _ bool) error {
	var all []subscription.Node
	var failures []error
	members := make(map[string][]string)
	for _, src := range sources {
		raw, err := s.fetchSubscription(ctx, src.URL)
		if err != nil {
			failures = append(failures, fmt.Errorf("subscription %s: fetch failed", src.Name))
			s.warn(fmt.Sprintf("fetch %s failed", src.Name))
			continue
		}
		nodes, parseErrs := subscription.ParseSubscription(raw)
		if len(parseErrs) > 0 {
			failures = append(failures, fmt.Errorf("%s: malformed subscription; previous membership retained", src.Name))
			s.warn(fmt.Sprintf("%s: invalid feed; sync skipped", src.Name))
			continue
		}
		all = append(all, nodes...)
		ids := make([]string, 0, len(nodes))
		seen := make(map[string]bool)
		for _, n := range nodes {
			id := store.NodeID(n)
			if !seen[id] {
				ids = append(ids, id)
				seen[id] = true
			}
		}
		members[src.ID] = ids
	}
	s.mu.Lock()
	s.job.SourcesOK, s.job.NodesParsed = len(members), len(all)
	s.mu.Unlock()
	if len(members) == 0 {
		return fmt.Errorf("api: no valid subscription responses: %w", errors.Join(failures...))
	}
	// Each successful feed is authoritative, even if another source failed.
	s.opMu.Lock()
	before := s.cfg.Store.All()
	// Build the replacement in memory; publish nodes.json only once.
	recordMap := map[string]store.Record{}
	for _, r := range before {
		recordMap[r.ID] = r
	}
	added, updated := 0, 0
	now := time.Now().UTC()
	for _, n := range all {
		id := store.NodeID(n)
		if r, ok := recordMap[id]; ok {
			r.Node = n
			r.UpdatedAt = now
			recordMap[id] = r
			updated++
		} else {
			recordMap[id] = store.Record{ID: id, Node: n, Enabled: true, CreatedAt: now, UpdatedAt: now, LastLatencyMS: store.LatencyUnmeasured}
			added++
		}
	}
	records := make([]store.Record, 0, len(recordMap))
	for _, r := range recordMap {
		records = append(records, r)
	}
	var err error
	s.mu.Lock()
	s.job.NodesAdded, s.job.NodesUpdated = added, updated
	previous := s.state.Subscriptions
	s.state.Subscriptions = append([]Subscription(nil), previous...)
	candidates := map[string]bool{}
	for i, sub := range s.state.Subscriptions {
		if ids, ok := members[sub.ID]; ok {
			for _, id := range sub.NodeIDs {
				candidates[id] = true
			}
			s.state.Subscriptions[i].NodeIDs = ids
		}
	}
	keep := map[string]bool{}
	for id, v := range s.state.ManualNodeIDs {
		if v {
			keep[id] = true
		}
	}
	for _, sub := range s.state.Subscriptions {
		for _, id := range sub.NodeIDs {
			keep[id] = true
		}
	}
	remove := map[string]bool{}
	for id := range candidates {
		if !keep[id] {
			remove[id] = true
		}
	}
	invalid := map[string]bool{}
	for id := range remove {
		invalid[id] = true
	}
	changed := true
	for changed {
		changed = false
		for _, r := range records {
			if !invalid[r.ID] && invalid[r.DetourID] {
				invalid[r.ID] = true
				changed = true
			}
		}
	}
	oldRoutes := s.state.DeviceRoutes
	s.state.DeviceRoutes = withoutRoutes(oldRoutes, invalid)
	oldAuto, oldSelected := s.state.AutoSelect, s.state.SelectedNodeID
	if invalid[s.state.SelectedNodeID] {
		s.state.AutoSelect = true
		s.state.SelectedNodeID = ""
	}
	remaining := make([]store.Record, 0, len(records))
	removed := 0
	for _, r := range records {
		if remove[r.ID] {
			removed++
			continue
		}
		// Legacy mutable chains lose their hop: disable rather than silently bypass it.
		if invalid[r.ID] {
			r.Enabled = false
			r.DetourID = ""
			r.Node.Detour = ""
			r.LastError = "Chain hop removed by subscription sync; rebuild the chain"
		}
		remaining = append(remaining, r)
	}
	err = s.cfg.Store.ReplaceRecords(remaining)
	if err == nil {
		err = s.saveState()
	}
	if err != nil {
		s.state.Subscriptions = previous
		s.state.DeviceRoutes = oldRoutes
		s.state.AutoSelect = oldAuto
		s.state.SelectedNodeID = oldSelected
		err = errors.Join(err, s.cfg.Store.ReplaceRecords(before))
		s.mu.Unlock()
		s.opMu.Unlock()
		return err
	}
	s.job.NodesPruned = removed
	s.mu.Unlock()
	for _, source := range sources {
		if ids, ok := members[source.ID]; ok {
			s.notify(fmt.Sprintf("Subscription refreshed: %s (%d nodes)", source.Name, len(ids)))
		}
	}
	// An empty successful feed may remove the last usable configuration.
	if len(s.cfg.Store.EnabledNodes()) == 0 && s.cfg.Engine.Running() {
		err = s.disable(ctx)
		if err == nil {
			s.mu.Lock()
			s.state.ProxyEnabled = false
			err = s.saveState()
			s.mu.Unlock()
		}
		s.opMu.Unlock()
		return err
	}
	// Apply removals immediately, before potentially slow latency probes.
	running := s.cfg.Engine.Running()
	err = s.reloadRunningLocked(ctx)
	s.mu.Lock()
	s.job.EngineReloaded = running && err == nil
	auto := s.state.AutoSelect
	s.mu.Unlock()
	s.opMu.Unlock()
	if err != nil {
		return err
	}
	if auto {
		return s.sweepLatency(ctx)
	}
	return nil
}

func unionIDs(a, b []string) []string {
	out := append([]string(nil), a...)
	seen := make(map[string]bool)
	for _, id := range a {
		seen[id] = true
	}
	for _, id := range b {
		if !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out
}

func (s *Service) StartLatencyTest(nodeID, subscriptionID string) (JobStatus, error) {
	if s.cfg.Tester == nil {
		return JobStatus{}, ErrNoTester
	}
	if (nodeID == "") == (subscriptionID == "") {
		return JobStatus{}, fmt.Errorf("%w: choose a node or subscription", ErrInvalidInput)
	}
	wanted := make(map[string]bool)
	if nodeID != "" {
		rec, err := s.cfg.Store.Get(nodeID)
		if err != nil {
			return JobStatus{}, err
		}
		if rec.Node.Protocol == subscription.ProtoBalance {
			return JobStatus{}, fmt.Errorf("%w: latency-test individual members", ErrInvalidInput)
		}
		wanted[nodeID] = true
	} else {
		found := false
		for _, sub := range s.subscriptionSnapshot() {
			if sub.ID == subscriptionID {
				found = true
				for _, id := range sub.NodeIDs {
					wanted[id] = true
				}
				break
			}
		}
		if !found {
			return JobStatus{}, store.ErrNotFound
		}
		if len(wanted) == 0 {
			return JobStatus{}, fmt.Errorf("%w: refresh this subscription before testing it", ErrInvalidInput)
		}
	}
	return s.startJob(JobStatus{Kind: "latency", NodeID: nodeID, SubscriptionID: subscriptionID}, func(ctx context.Context) error { return s.testSelectedNodes(ctx, wanted) })
}

func (s *Service) testSelectedNodes(ctx context.Context, wanted map[string]bool) error {
	records := s.cfg.Store.All()
	all := make([]subscription.Node, len(records))
	for i, rec := range records {
		all[i] = rec.Node
	}
	subscription.DedupeTags(all)
	tags := map[string]string{}
	for i, r := range records {
		tags[r.ID] = all[i].Tag
	}
	for i, r := range records {
		if r.DetourID != "" {
			all[i].Detour = tags[r.DetourID]
		}
	}
	var nodes []subscription.Node
	var ids []string
	for i, rec := range records {
		if wanted[rec.ID] {
			nodes = append(nodes, all[i])
			ids = append(ids, rec.ID)
		}
	}
	if len(nodes) == 0 {
		return store.ErrNotFound
	}
	var results []tester.Result
	if selected, ok := s.cfg.Tester.(interface {
		TestSelectedNodes(context.Context, []subscription.Node, []subscription.Node) []tester.Result
	}); ok {
		results = selected.TestSelectedNodes(ctx, nodes, all)
	} else {
		results = s.cfg.Tester.TestNodes(ctx, nodes)
	}
	if len(results) != len(ids) {
		return errors.New("latency tester returned incomplete results")
	}
	reachable := 0
	for i, result := range results {
		var err error
		if result.OK() {
			reachable++
			err = s.cfg.Store.RecordLatency(ids[i], result.Latency)
		} else {
			err = s.cfg.Store.RecordFailure(ids[i], result.Err)
		}
		if err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.job.Tested, s.job.Reachable = len(results), reachable
	s.mu.Unlock()
	return ctx.Err()
}
