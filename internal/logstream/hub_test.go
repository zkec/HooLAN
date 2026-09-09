package logstream

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestReplayIsBoundedAndSlowSubscribersAreDisconnected(t *testing.T) {
	hub := New()
	_, slow, cancel, err := hub.Subscribe(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	for i := 0; i < 700; i++ {
		hub.Publish("INFO", "test", "line")
	}
	history, _, stop, err := hub.Subscribe(0)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if len(history) != maxEntries || history[0].ID != 189 || history[len(history)-1].ID != 700 {
		t.Fatalf("unexpected retained history: len=%d first=%d last=%d", len(history), history[0].ID, history[len(history)-1].ID)
	}
	count := 0
	for range slow {
		count++
	}
	if count != subscriberBuffer {
		t.Fatalf("slow buffer=%d", count)
	}
	history, _, stop2, err := hub.Subscribe(698)
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()
	if len(history) != 2 || history[0].ID != 699 {
		t.Fatalf("cursor replay=%v", history)
	}
	hub.Close()
	if _, _, _, err := hub.Subscribe(0); err == nil {
		t.Fatal("closed hub accepted subscriber")
	}
}

func TestTeeCapturesEngineSourceAndRedactsCredentials(t *testing.T) {
	hub := New("manager-private-token", "clash-private-secret")
	logger := slog.New(NewTeeHandler(slog.NewTextHandler(io.Discard, nil), hub)).With("src", "engine")
	logger.Info("dial failed manager-private-token clash-private-secret vless://node-uuid@host:443?secret=value https://user:password@example.com/path-token?access=query-token Bearer bearer-value",
		"src", "sing-box", "password", "attribute-secret", "uuid", "attribute-uuid")
	history, _, cancel, err := hub.Subscribe(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if len(history) != 1 || history[0].Source != "sing-box" {
		t.Fatalf("history=%+v", history)
	}
	message := history[0].Message
	for _, secret := range []string{"manager-private-token", "clash-private-secret", "node-uuid", "user:password", "path-token", "query-token", "bearer-value", "attribute-secret", "attribute-uuid"} {
		if strings.Contains(message, secret) {
			t.Errorf("leaked %q in %q", secret, message)
		}
	}
	if !strings.Contains(message, "example.com") || !strings.Contains(message, "redacted") {
		t.Errorf("missing useful redacted context: %s", message)
	}
}

func TestTeeHonorsLevelsAndGroups(t *testing.T) {
	hub := New()
	logger := slog.New(NewTeeHandler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}), hub))
	logger.Info("suppressed")
	logger.WithGroup("request").With("path", "/api/status").WithGroup("nested").WarnContext(context.Background(), "failed", "status", 503)
	history, _, cancel, _ := hub.Subscribe(0)
	defer cancel()
	if len(history) != 1 {
		t.Fatalf("history count=%d", len(history))
	}
	if !strings.Contains(history[0].Message, "request.path=/api/status") || !strings.Contains(history[0].Message, "request.nested.status=503") {
		t.Fatalf("group attrs lost: %s", history[0].Message)
	}
}
