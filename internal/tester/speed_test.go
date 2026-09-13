package tester

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type speedTransport func(*http.Request) (*http.Response, error)

func (f speedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func TestSpeedPayloadAndCalculation(t *testing.T) {
	client := &http.Client{Transport: speedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != SpeedURL || r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatal("wrong speed request")
		}
		return &http.Response{StatusCode: 200, ContentLength: SpeedBytes, Body: io.NopCloser(io.LimitReader(zeroReader{}, SpeedBytes)), Header: make(http.Header)}, nil
	})}
	result, err := measureSpeed(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bytes != SpeedBytes || result.Mbps <= 0 || result.Seconds <= 0 {
		t.Fatal("invalid speed result")
	}
	client.Transport = speedTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Body: io.NopCloser(strings.NewReader("short")), Header: make(http.Header)}, nil
	})
	if _, err := measureSpeed(context.Background(), client); err == nil {
		t.Fatal("partial download accepted")
	}
}

func TestSpeedFallsBackAfter403(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: speedTransport(func(r *http.Request) (*http.Response, error) {
		endpoint := speedEndpoints[calls]
		calls++
		if r.URL.String() != endpoint.URL {
			t.Fatalf("wrong fallback: %s", r.URL)
		}
		if calls == 1 {
			return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("Forbidden"))}, nil
		}
		return &http.Response{StatusCode: 200, ContentLength: endpoint.Bytes, Body: io.NopCloser(io.LimitReader(zeroReader{}, endpoint.Bytes)), Header: make(http.Header)}, nil
	})}
	result, err := measureSpeed(context.Background(), client)
	if err != nil || calls != 2 || result.Bytes != 10*1024*1024 || result.Server != "speedtest.netone.nl" || result.Mbps <= 0 {
		t.Fatalf("fallback result: %+v %v (calls %d)", result, err, calls)
	}
}

func TestSpeedRejectsErrorPagesAndStopsOnCancellation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		kind, encoding string
	}{
		{"html", 200, "text/html", ""}, {"json", 200, "application/json", ""}, {"gzip", 200, "application/octet-stream", "gzip"}, {"denied", 403, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: speedTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: tc.status, ContentLength: SpeedBytes, Header: http.Header{"Content-Type": {tc.kind}, "Content-Encoding": {tc.encoding}}, Body: io.NopCloser(io.LimitReader(zeroReader{}, SpeedBytes))}, nil
			})}
			result, err := measureSpeed(context.Background(), client)
			if err == nil || result.Mbps != 0 || calls != 2 {
				t.Fatalf("bad payload accepted: %+v %v", result, err)
			}
			if !strings.Contains(err.Error(), "speed.cloudflare.com") || !strings.Contains(err.Error(), "speedtest.netone.nl") {
				t.Fatal("missing endpoint diagnostics")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	client := &http.Client{Transport: speedTransport(func(*http.Request) (*http.Response, error) { calls++; cancel(); return nil, context.Canceled })}
	if _, err := measureSpeed(ctx, client); err != context.Canceled || calls != 1 {
		t.Fatalf("retried cancelled request: %v %d", err, calls)
	}
}
