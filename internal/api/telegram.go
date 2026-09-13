package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

type TelegramSettings struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	ChatID  string `json:"chat_id"`
}

var botTokenPattern = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$`)
var chatIDPattern = regexp.MustCompile(`^(?:-?[0-9]{1,20}|@[A-Za-z0-9_]{5,64})$`)

func validateTelegram(v TelegramSettings) error {
	if v.Token != "" && !botTokenPattern.MatchString(v.Token) {
		return fmt.Errorf("%w: invalid Telegram bot token", ErrInvalidInput)
	}
	if v.ChatID != "" && !chatIDPattern.MatchString(v.ChatID) {
		return fmt.Errorf("%w: invalid Telegram chat ID", ErrInvalidInput)
	}
	if v.Enabled && (v.Token == "" || v.ChatID == "") {
		return fmt.Errorf("%w: Telegram token and chat ID are required", ErrInvalidInput)
	}
	return nil
}
func sendTelegram(ctx context.Context, client *http.Client, cfg TelegramSettings, message string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": cfg.ChatID, "text": message, "link_preview_options": map[string]bool{"is_disabled": true}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+cfg.Token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid Telegram request")
	}
	req.Header.Set("Content-Type", "application/json")
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := safe.Do(req)
	if err != nil {
		return errors.New("Telegram delivery failed (network or timeout)")
	} // never log URL/token
	defer resp.Body.Close()
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return errors.New("invalid Telegram response")
	}
	if resp.StatusCode != 200 || !result.OK {
		return fmt.Errorf("Telegram rejected notification (HTTP %d)", resp.StatusCode)
	}
	return nil
}
func (s *Service) telegram(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		defer s.mu.RUnlock()
		v := s.state.Telegram
		writeJSON(w, 200, map[string]any{"enabled": v.Enabled, "chat_id": v.ChatID, "token_set": v.Token != "", "last_error": s.telegramError})
	case http.MethodPut:
		var req struct {
			Enabled bool    `json:"enabled"`
			Token   *string `json:"token"`
			ChatID  string  `json:"chat_id"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		s.opMu.Lock()
		defer s.opMu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		old := s.state.Telegram
		next := TelegramSettings{Enabled: req.Enabled, ChatID: req.ChatID, Token: old.Token}
		if req.Token != nil {
			next.Token = *req.Token
		}
		if err := validateTelegram(next); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		s.state.Telegram = next
		if err := s.saveState(); err != nil {
			s.state.Telegram = old
			writeError(w, 500, "could not save notification settings")
			return
		}
		s.telegramError = ""
		writeJSON(w, 200, map[string]string{"message": "Notification settings saved"})
	default:
		methodsNotAllowed(w, "GET, PUT")
	}
}

// Notifications are best-effort and never hold up engine or firewall operations.
func (s *Service) notify(message string) {
	s.mu.RLock()
	enabled := s.state.Telegram.Enabled && !s.closing
	s.mu.RUnlock()
	if !enabled {
		return
	}
	select {
	case s.notifications <- message:
	default:
		s.log.Warn("notification queue full; alert dropped")
	}
}
func (s *Service) startNotifications() {
	s.mu.Lock()
	if s.notificationsStarted || s.closing {
		s.mu.Unlock()
		return
	}
	s.notificationsStarted = true
	s.jobs.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.jobs.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.jobCtx.Done():
				return
			case msg := <-s.notifications:
				s.mu.RLock()
				cfg := s.state.Telegram
				s.mu.RUnlock()
				if !cfg.Enabled {
					continue
				}
				ctx, cancel := context.WithTimeout(s.jobCtx, 10*time.Second)
				client := s.cfg.NotificationClient
				if client == nil {
					client = &http.Client{Timeout: 10 * time.Second}
				}
				err := sendTelegram(ctx, client, cfg, msg)
				cancel()
				s.mu.Lock()
				s.telegramError = ""
				if err != nil {
					s.telegramError = err.Error()
				}
				s.mu.Unlock()
			case <-ticker.C:
				s.checkActiveNode()
			}
		}
	}()
}
func (s *Service) activeNodeID(ctx context.Context) string {
	choice := s.selection(ctx)
	if !choice.Auto {
		return choice.NodeID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, tag := range s.tagByID {
		if tag == choice.AutoPick {
			return id
		}
	}
	return ""
}
func (s *Service) checkActiveNode() {
	s.mu.RLock()
	enabled := s.state.Telegram.Enabled && s.proxyEnabled && !s.refreshing
	s.mu.RUnlock()
	if !enabled || s.cfg.Tester == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.jobCtx, 3*time.Second)
	id := s.activeNodeID(ctx)
	cancel()
	if id == "" {
		return
	}
	_, _ = s.startJob(JobStatus{Kind: "health", NodeID: id}, func(ctx context.Context) error {
		err := s.testSelectedNodes(ctx, map[string]bool{id: true})
		if err != nil {
			return err
		}
		rec, err := s.cfg.Store.Get(id)
		if err != nil {
			return err
		}
		if ctx.Err() != nil || s.activeNodeID(ctx) != id {
			return nil
		}
		s.mu.Lock()
		previous := s.failedActive
		s.failedActive = ""
		failed := !rec.Healthy()
		if failed {
			s.failedActive = id
		}
		s.mu.Unlock()
		if failed && previous != id {
			s.notify(fmt.Sprintf("Active node failed its background latency check: %s", rec.Node.Tag))
		}
		return nil
	})
}

// Shutdown has already cancelled the worker; make one bounded final attempt.
func (s *Service) notifyShutdown(ctx context.Context) {
	s.mu.RLock()
	cfg := s.state.Telegram
	s.mu.RUnlock()
	if !cfg.Enabled {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client := s.cfg.NotificationClient
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	if err := sendTelegram(ctx, client, cfg, "Proxy engine stopped during service shutdown."); err != nil {
		s.log.Warn("shutdown notification was not delivered", "err", err)
	}
}
