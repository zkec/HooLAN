package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fixtureTransport struct {
	bodies map[string]string
	calls  []string
}

func (f *fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(f.bodies[r.URL.RequestURI()])), Header: make(http.Header)}, nil
}
func fixture(t *testing.T, rootless bool, items ...container) (*Client, *fixtureTransport) {
	t.Helper()
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	info := `{"SecurityOptions":[]}`
	if rootless {
		info = `{"SecurityOptions":["name=rootless"]}`
	}
	f := &fixtureTransport{bodies: map[string]string{"/info": info, "/networks": `[{"Id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Name":"stack","Driver":"bridge","Scope":"local","Options":{"com.docker.network.bridge.name":"br-stack"}}]`, "/containers/json?all=1": string(raw)}}
	return &Client{http: &http.Client{Transport: f}, bridgeExists: func(name string) bool { return name == "br-stack" }}, f
}
func sample(id, name, ip string) container {
	c := container{ID: strings.Repeat(id, 64), Names: []string{"/" + name}, Image: "example:latest", State: "running", Labels: map[string]string{"com.docker.compose.project": "stack", "com.docker.compose.service": name, "com.docker.compose.container-number": "1"}}
	c.HostConfig.NetworkMode = "stack"
	c.NetworkSettings.Networks = map[string]endpoint{"stack": {NetworkID: strings.Repeat("a", 64), IPAddress: ip}}
	return c
}
func TestInventoryStableIdentityAndReadOnly(t *testing.T) {
	c, f := fixture(t, false, sample("b", "app", "172.18.0.3"))
	first, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || !first[0].Supported || first[0].Bindings[0].Bridge != "br-stack" {
		t.Fatalf("bad inventory: %+v", first)
	}
	replacement := sample("c", "app", "172.18.0.8")
	replacement.Names = []string{"/new-compose-container-name"}
	raw, _ := json.Marshal([]container{replacement})
	f.bodies["/containers/json?all=1"] = string(raw)
	second, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Key != second[0].Key || second[0].ID == first[0].ID || second[0].Bindings[0].IP != "172.18.0.8" {
		t.Fatal("Compose identity did not survive recreation")
	}
	for _, call := range f.calls {
		if !strings.HasPrefix(call, "GET ") {
			t.Fatal("Docker mutation: " + call)
		}
	}
}
func TestUnsupportedNetworksAndDuplicateIPs(t *testing.T) {
	a := sample("b", "app", "172.18.0.3")
	b := sample("c", "other", "172.18.0.3")
	c, _ := fixture(t, false, a, b)
	items, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Supported || !strings.Contains(item.Reason, "shared") {
			t.Fatalf("ambiguous IP accepted: %+v", item)
		}
	}
	for _, mode := range []string{"host", "none", "container:abc"} {
		a.HostConfig.NetworkMode = mode
		c, _ = fixture(t, false, a)
		items, err = c.List(context.Background())
		if err != nil || items[0].Supported {
			t.Fatal("unsupported mode accepted: " + mode)
		}
	}
	a.HostConfig.NetworkMode = "stack"
	c, _ = fixture(t, true, a)
	items, _ = c.List(context.Background())
	if items[0].Supported {
		t.Fatal("rootless accepted")
	}
	c, _ = fixture(t, false, a)
	c.bridgeExists = func(string) bool { return false }
	items, _ = c.List(context.Background())
	if items[0].Supported {
		t.Fatal("absent bridge accepted")
	}
	a.State = "exited"
	c, _ = fixture(t, false, a)
	items, _ = c.List(context.Background())
	if items[0].Supported || len(items) != 1 {
		t.Fatal("stopped container missing/controllable")
	}
}
func TestInvalidAndBoundedAPIResponses(t *testing.T) {
	c, f := fixture(t, false, sample("b", "app", "172.18.0.3"))
	f.bodies["/containers/json?all=1"] = "not json"
	if _, err := c.List(context.Background()); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	f.bodies["/info"] = strings.Repeat("x", 8*1024*1024+1)
	if _, err := c.List(context.Background()); err == nil {
		t.Fatal("unbounded response")
	}
	if _, err := New("relative.sock"); err == nil {
		t.Fatal("nonlocal socket accepted")
	}
	if c, err := New(""); err != nil || c != nil {
		t.Fatal("cannot disable Docker discovery")
	}
}
