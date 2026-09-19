package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"hoolan/internal/engine"
	"hoolan/internal/netfilter"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
)

const maxBackupBytes = 32 << 20

type backupNodes struct {
	Version int            `json:"version"`
	SavedAt time.Time      `json:"saved_at"`
	Records []store.Record `json:"records"`
}
type backupDevices struct {
	Routes  map[string]string `json:"routes"`
	Aliases map[string]string `json:"aliases"`
}
type backupBundle struct {
	Nodes backupNodes
	State State
	Conf  []byte
}

func (s *Service) backupConfigPath() (string, error) {
	fw, ok := s.cfg.Firewall.(interface{ ConfigPath() string })
	if !ok || fw.ConfigPath() == "" {
		return "", errors.New("firewall does not expose a backup configuration path")
	}
	return fw.ConfigPath(), nil
}
func (s *Service) makeBackup() ([]byte, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closing || s.refreshing {
		s.mu.Unlock()
		return nil, ErrRefreshInProgress
	}
	s.refreshing = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.refreshing = false; s.mu.Unlock() }()
	path, err := s.backupConfigPath()
	if err != nil {
		return nil, err
	}
	conf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := netfilter.ValidateBackupConfig(conf, s.cfg.Engine.TProxyPort()); err != nil {
		return nil, err
	}
	s.mu.RLock()
	state, err := json.Marshal(s.state)
	devices, devErr := json.Marshal(backupDevices{s.state.DeviceRoutes, s.state.DeviceAliases})
	s.mu.RUnlock()
	if err != nil || devErr != nil {
		return nil, errors.Join(err, devErr)
	}
	nodes, err := json.Marshal(backupNodes{1, time.Now().UTC(), s.cfg.Store.All()})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	entries := []struct {
		name string
		data []byte
	}{{"nodes.json", nodes}, {"state.json", state}, {"tproxy.conf", conf}, {"devices.json", devices}}
	size := 0
	for _, entry := range entries {
		size += len(entry.data)
		if size > maxBackupBytes {
			return nil, errors.New("backup exceeds size limit")
		}
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(0600)
		out, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err = out.Write(entry.data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func decodeBackup(raw []byte, port int) (backupBundle, error) {
	var out backupBundle
	if len(raw) > maxBackupBytes {
		return out, fmt.Errorf("backup is too large")
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return out, fmt.Errorf("invalid ZIP archive")
	}
	if len(reader.File) != 4 {
		return out, fmt.Errorf("backup must contain exactly nodes.json, state.json, tproxy.conf and devices.json")
	}
	allowed := map[string]bool{"nodes.json": true, "state.json": true, "tproxy.conf": true, "devices.json": true}
	files := map[string][]byte{}
	total := int64(0)
	for _, f := range reader.File {
		if !allowed[f.Name] || files[f.Name] != nil || !f.Mode().IsRegular() {
			return out, fmt.Errorf("unexpected, duplicate or non-regular ZIP entry")
		}
		if f.UncompressedSize64 > maxBackupBytes {
			return out, fmt.Errorf("expanded backup exceeds size limit")
		}
		r, err := f.Open()
		if err != nil {
			return out, err
		}
		data, readErr := io.ReadAll(io.LimitReader(r, maxBackupBytes-total+1))
		r.Close()
		if readErr != nil {
			return out, readErr
		}
		total += int64(len(data))
		if total > maxBackupBytes {
			return out, fmt.Errorf("expanded backup exceeds size limit")
		}
		files[f.Name] = data
	}
	if err := json.Unmarshal(files["nodes.json"], &out.Nodes); err != nil {
		return out, fmt.Errorf("invalid nodes.json")
	}
	if err := json.Unmarshal(files["state.json"], &out.State); err != nil {
		return out, fmt.Errorf("invalid state.json")
	}
	var devices backupDevices
	if err := json.Unmarshal(files["devices.json"], &devices); err != nil {
		return out, fmt.Errorf("invalid devices.json")
	}
	if !maps.Equal(devices.Routes, out.State.DeviceRoutes) || !maps.Equal(devices.Aliases, out.State.DeviceAliases) {
		return out, fmt.Errorf("device mappings disagree with state.json")
	}
	out.Conf = files["tproxy.conf"]
	if err := netfilter.ValidateBackupConfig(out.Conf, port); err != nil {
		return out, err
	}
	if out.Nodes.Version != 1 {
		return out, fmt.Errorf("unsupported node store version")
	}
	byID := map[string]store.Record{}
	nodes := []subscription.Node{}
	tags := map[string]string{}
	for _, r := range out.Nodes.Records {
		if r.ID == "" || r.ID != store.NodeID(r.Node) {
			return out, fmt.Errorf("invalid node identity")
		}
		if _, dup := byID[r.ID]; dup {
			return out, fmt.Errorf("duplicate node")
		}
		if err := r.Node.Validate(); err != nil {
			return out, fmt.Errorf("invalid node: %w", err)
		}
		if _, err := engine.RenderOutbound(r.Node); err != nil {
			return out, fmt.Errorf("unsupported node: %w", err)
		}
		byID[r.ID] = r
		if r.Enabled {
			nodes = append(nodes, r.Node)
		}
	}
	subscription.DedupeTags(nodes)
	for _, n := range nodes {
		tags[store.NodeID(n)] = n.Tag
	}
	for i, n := range nodes {
		if dep := byID[store.NodeID(n)].DetourID; dep != "" {
			if tags[dep] == "" {
				return out, fmt.Errorf("missing chain hop")
			}
			nodes[i].Detour = tags[dep]
		}
	}
	store.ResolveBalanceMembers(nodes)
	if _, err := engine.DistributionPlan(nodes, port); err != nil {
		return out, err
	}
	if err := subscription.ValidateChains(nodes); err != nil {
		return out, err
	}
	state := &out.State
	if err := netfilter.ValidateDeviceLimits(state.DeviceLimits); err != nil {
		return out, err
	}
	if state.ProxyEnabled && len(nodes) == 0 {
		return out, fmt.Errorf("enabled backup has no enabled nodes")
	}
	if state.SelectedNodeID != "" {
		r, ok := byID[state.SelectedNodeID]
		if !ok || !r.Enabled || r.Node.ChainInternal {
			return out, fmt.Errorf("invalid selected node")
		}
	}
	for ip, id := range state.DeviceRoutes {
		if normalized, err := deviceIP(ip); err != nil || normalized != ip {
			return out, fmt.Errorf("invalid device IP")
		}
		if id != "direct" {
			r, ok := byID[id]
			if !ok || !r.Enabled || r.Node.ChainInternal {
				return out, fmt.Errorf("invalid device route")
			}
		}
	}
	for ip, alias := range state.DeviceAliases {
		if normalized, err := deviceIP(ip); err != nil || normalized != ip || !utf8.ValidString(alias) || utf8.RuneCountInString(alias) > 80 || strings.IndexFunc(alias, unicode.IsControl) >= 0 {
			return out, fmt.Errorf("invalid device alias")
		}
	}
	for id := range state.ManualNodeIDs {
		if _, ok := byID[id]; !ok {
			return out, fmt.Errorf("invalid manual ownership")
		}
	}
	for _, sub := range state.Subscriptions {
		u, err := url.Parse(sub.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return out, fmt.Errorf("restored subscriptions must use HTTP(S) URLs")
		}
		for _, id := range sub.NodeIDs {
			if _, ok := byID[id]; !ok {
				return out, fmt.Errorf("invalid subscription membership")
			}
		}
	}
	if _, err := engine.NormalizeDNSServer(state.DNSServer); err != nil {
		return out, err
	}
	direct := state.DirectDNS
	if direct == "" {
		direct = state.DNSServer
	}
	_, direct, err = engine.NormalizeSplitDNS(state.TunneledDoH, direct)
	if err != nil {
		return out, err
	}
	listener, err := engine.NormalizeFakeDNS(state.FakeDNS)
	if err != nil {
		return out, err
	}
	if err := engine.ValidateDNSListener(direct, listener.Listen); err != nil {
		return out, err
	}
	if state.RulePolicy != nil {
		if err := engine.ValidateRulePolicy(*state.RulePolicy); err != nil {
			return out, err
		}
	}
	if err := validateTelegram(state.Telegram); err != nil {
		return out, err
	}
	// Never trust filesystem paths or engine-specific baselines from another host.
	if state.ManualNodeIDs == nil {
		state.ManualNodeIDs = map[string]bool{}
	}
	state.RuleFiles = nil
	state.RuleLastUpdate = time.Time{}
	state.RuleLastAttempt = time.Time{}
	state.RuleError = ""
	state.Usage.PID = 0
	state.Usage.Previous = Bytes{}
	return out, nil
}
func atomicBackupWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".restore-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return os.Rename(name, path)
}
func (s *Service) applyBackup(ctx context.Context, bundle backupBundle) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	path, err := s.backupConfigPath()
	if err != nil {
		return err
	}
	oldConf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	oldNodes := s.cfg.Store.All()
	s.mu.RLock()
	oldState := s.state
	s.mu.RUnlock()
	wasRunning := s.cfg.Engine.Running()
	// Remove using the OLD mark/table before replacing the shell configuration.
	if err := s.disable(ctx); err != nil {
		return err
	}
	rollback := func(cause error) error {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// If new interception cannot be removed, retain its config so OFF can retry.
		if err := s.disable(cleanCtx); err != nil {
			return errors.Join(cause, fmt.Errorf("cleanup failed; restored firewall config retained: %w", err))
		}
		err := atomicBackupWrite(path, oldConf)
		err = errors.Join(err, s.cfg.Store.ReplaceRecords(oldNodes))
		s.mu.Lock()
		s.state = oldState
		s.usageSeen = nil
		err = errors.Join(err, s.saveState())
		s.mu.Unlock()
		err = errors.Join(err, s.configureEngineRouting(), s.syncDeviceLimits(cleanCtx))
		if err == nil && wasRunning && oldState.ProxyEnabled {
			err = s.enable(cleanCtx)
		}
		return errors.Join(cause, err)
	}
	if err := atomicBackupWrite(path, bundle.Conf); err != nil {
		return rollback(err)
	}
	if err := s.cfg.Store.ReplaceRecords(bundle.Nodes.Records); err != nil {
		return rollback(err)
	}
	s.mu.Lock()
	s.state = bundle.State
	s.usageSeen = nil
	s.failedActive = ""
	s.tagByID = map[string]string{}
	err = s.saveState()
	s.mu.Unlock()
	if err == nil {
		err = errors.Join(s.configureEngineRouting(), s.syncDeviceLimits(ctx))
	}
	if err == nil && bundle.State.ProxyEnabled {
		err = s.enable(ctx)
	}
	if err != nil {
		return rollback(err)
	}
	return nil
}
func (h *handlers) backup(w http.ResponseWriter, r *http.Request) {
	data, err := h.svc.makeBackup()
	if err != nil {
		h.dashboardError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="backup.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}
func (h *handlers) restoreBackup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 413, "Backup upload exceeds 32 MiB")
		return
	}
	bundle, err := decodeBackup(raw, h.svc.cfg.Engine.TProxyPort())
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	job, err := h.svc.startJob(JobStatus{Kind: "restore"}, func(ctx context.Context) error { return h.svc.applyBackup(ctx, bundle) })
	h.writeJob(w, job, err)
}
