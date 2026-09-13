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
