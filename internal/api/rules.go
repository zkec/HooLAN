package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"proxy-manager/internal/engine"
)

type ruleManager interface {
	ConfigureRulePolicy(engine.RulePolicy, map[string]string) error
	FetchRuleSets(context.Context, engine.RulePolicy) (map[string]string, error)
}
type RuleStatus struct {
	Policy      engine.RulePolicy `json:"policy"`
	LastUpdate  time.Time         `json:"last_update"`
	LastAttempt time.Time         `json:"last_attempt"`
	NextUpdate  time.Time         `json:"next_update"`
	Files       map[string]string `json:"files"`
	Error       string            `json:"error"`
}

func (s *Service) rulePolicyLocked() engine.RulePolicy {
	if s.state.RulePolicy == nil {
		return engine.DefaultRulePolicy()
	}
	return engine.CloneRulePolicy(*s.state.RulePolicy)
}
func (s *Service) Rules() RuleStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := RuleStatus{Policy: s.rulePolicyLocked(), LastUpdate: s.state.RuleLastUpdate, LastAttempt: s.state.RuleLastAttempt, Error: s.state.RuleError}
	r.Files = map[string]string{}
	for _, u := range r.Policy.SourceURLs() {
		if p := s.state.RuleFiles[u]; p != "" {
			r.Files[u] = p
		}
	}
	anchor := r.LastUpdate
	if anchor.IsZero() || s.state.RuleScheduleAnchor.After(anchor) {
		anchor = s.state.RuleScheduleAnchor
	}
	r.NextUpdate = engine.NextRuleUpdate(r.Policy, anchor, time.Now())
	if !r.NextUpdate.IsZero() {
		retry := r.LastAttempt.Add(time.Hour)
		if retry.After(r.NextUpdate) {
			r.NextUpdate = retry
		}
	}

	return r
}
func (s *Service) configureRulePolicy() error {
	manager, ok := s.cfg.Engine.(ruleManager)
	if !ok {
		return nil
	}
	s.mu.RLock()
	p := s.rulePolicyLocked()
	files := make(map[string]string, len(s.state.RuleFiles))
	for k, v := range s.state.RuleFiles {
		files[k] = v
	}
	s.mu.RUnlock()
	return manager.ConfigureRulePolicy(p, files)
}
func (s *Service) UpdateRules(ctx context.Context, p engine.RulePolicy) (RuleStatus, error) {
	if err := engine.ValidateRulePolicy(p); err != nil {
		return s.Rules(), fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if _, ok := s.cfg.Engine.(ruleManager); !ok {
		return s.Rules(), errors.New("engine does not support rule management")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closing || s.refreshing {
		s.mu.Unlock()
		return s.Rules(), ErrRefreshInProgress
	}
	old := s.state.RulePolicy
	oldUpdate := s.state.RuleLastUpdate
	oldAnchor := s.state.RuleScheduleAnchor
	previous := s.rulePolicyLocked()
	p = engine.CloneRulePolicy(p)
	s.state.RulePolicy = &p
	s.state.RuleScheduleAnchor = time.Now().UTC()
	if !reflect.DeepEqual(previous.SourceURLs(), p.SourceURLs()) {
		s.state.RuleLastUpdate = time.Time{}
	}
	if err := s.saveState(); err != nil {
		s.state.RulePolicy = old
		s.state.RuleLastUpdate = oldUpdate
		s.state.RuleScheduleAnchor = oldAnchor
		s.mu.Unlock()
		return s.Rules(), err
	}
	s.mu.Unlock()
	err := s.configureRulePolicy()
	if err == nil {
		err = s.reloadRunningLocked(ctx)
	}
	if err != nil {
		s.mu.Lock()
		s.state.RulePolicy = old
		s.state.RuleLastUpdate = oldUpdate
		s.state.RuleScheduleAnchor = oldAnchor
		saveErr := s.saveState()
		s.mu.Unlock()
		err = errors.Join(err, saveErr, s.configureRulePolicy())
	}
	return s.Rules(), err
}
func (s *Service) StartRuleUpdate() (JobStatus, error) {
	if _, ok := s.cfg.Engine.(ruleManager); !ok {
		return JobStatus{}, errors.New("engine does not support rule updates")
	}
	return s.startJob(JobStatus{Kind: "rules", SourcesTotal: len(s.Rules().Policy.SourceURLs())}, s.updateRuleFiles)
}
func (s *Service) updateRuleFiles(ctx context.Context) (resultErr error) {
	s.mu.Lock()
	p := s.rulePolicyLocked()
	s.state.RuleLastAttempt = time.Now().UTC()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.state.RuleError = ""
		if resultErr != nil {
			s.state.RuleError = resultErr.Error()
		}
		resultErr = errors.Join(resultErr, s.saveState())
	}()
	manager := s.cfg.Engine.(ruleManager)
	files, err := manager.FetchRuleSets(ctx, p)
	if err != nil {
		return err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if !reflect.DeepEqual(p, s.rulePolicyLocked()) {
		s.mu.Unlock()
		return errors.New("routing sources changed during download; retry update")
	}
	oldFiles, oldTime := s.state.RuleFiles, s.state.RuleLastUpdate
	s.state.RuleFiles = files
	s.state.RuleLastUpdate = time.Now().UTC()
	if err := s.saveState(); err != nil {
		s.state.RuleFiles = oldFiles
		s.state.RuleLastUpdate = oldTime
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	err = s.configureRulePolicy()
	if err == nil {
		err = s.reloadRunningLocked(ctx)
	}
	if err != nil {
		s.mu.Lock()
		s.state.RuleFiles = oldFiles
		s.state.RuleLastUpdate = oldTime
		saveErr := s.saveState()
		s.mu.Unlock()
		return errors.Join(err, saveErr, s.configureRulePolicy())
	}
	s.mu.Lock()
	s.job.SourcesOK = len(files)
	s.job.EngineReloaded = s.cfg.Engine.Running()
	s.mu.Unlock()
	s.log.Info("GeoIP and geosite rule sets updated")
	return nil
}

// The control-plane scheduler also runs with the proxy OFF. Retries are bounded
// to hourly, and all updates share the existing cancellable background job slot.
func (s *Service) startRuleScheduler() {
	if _, ok := s.cfg.Engine.(ruleManager); !ok {
		return
	}
	s.mu.Lock()
	if s.closing || s.ruleSchedulerStarted {
		s.mu.Unlock()
		return
	}
	s.ruleSchedulerStarted = true
	s.jobs.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.jobs.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.jobCtx.Done():
				return
			case now := <-ticker.C:
				status := s.Rules()
				if !status.NextUpdate.IsZero() && !now.Before(status.NextUpdate) {
					if _, err := s.StartRuleUpdate(); err != nil && !errors.Is(err, ErrRefreshInProgress) {
						s.log.Warn("scheduled rule update could not start", "err", err)
					}
				}
			}
		}
	}()
}
func (h *handlers) rules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.svc.Rules())
	case http.MethodPut:
		var p engine.RulePolicy
		if err := decodeBody(r, &p); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		status, err := h.svc.UpdateRules(r.Context(), p)
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, 200, status)
	default:
		methodsNotAllowed(w, "GET, PUT")
	}
}
