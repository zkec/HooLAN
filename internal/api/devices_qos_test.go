package api

import (
	"context"
	"encoding/json"
	"hoolan/internal/netfilter"
	"reflect"
	"testing"
)

func TestFourWayDeviceSettingsRoundTripRollbackAndPartialUpdate(t *testing.T) {
	h, fw := balanceHarness(t)
	ip := "192.168.3.141"
	caps := netfilter.DeviceLimits{ProxyUpload: 1, ProxyDownload: 2, DirectUpload: 3, DirectDownload: 4}
	if err := h.svc.UpdateDevice(context.Background(), DeviceUpdate{IP: ip, Alias: strptr("Phone"), NodeID: strptr("direct"), QoS: &caps}); err != nil {
		t.Fatal(err)
	}
	persisted, err := h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.DeviceLimits[ip] != caps || fw.installed[ip] != caps || persisted.DeviceRoutes[ip] != "direct" {
		t.Fatal("four independent fields not persisted/applied")
	}
	if err := h.svc.UpdateDevice(context.Background(), DeviceUpdate{IP: ip, Alias: strptr("Tablet")}); err != nil {
		t.Fatal(err)
	}
	if fw.installed[ip] != caps || fw.syncs != 1 {
		t.Fatal("alias edit changed/reloaded QoS")
	}
	fw.failNext = true
	modified := caps
	modified.ProxyDownload = 9
	if err := h.svc.UpdateDevice(context.Background(), DeviceUpdate{IP: ip, Alias: strptr("Wrong"), QoS: &modified}); err == nil {
		t.Fatal("accepted rejected transaction")
	}
	persisted, _ = h.svc.loadState()
	if persisted.DeviceLimits[ip] != caps || fw.installed[ip] != caps || persisted.DeviceAliases[ip] != "Tablet" {
		t.Fatal("failed update did not roll back all fields")
	}
	for _, raw := range []string{
		`{"ip":"192.168.3.141","qos":{"proxy_upload_mbps":-1}}`,
		`{"ip":"192.168.3.141","qos":{"proxy_download_mbps":10001}}`,
		`{"ip":"192.168.3.141","qos":{"direct_upload_mbps":0.001}}`,
		`{"ip":"192.168.3.141","qos":{"direct_download_mbps":-2}}`,
		`{"ip":"192.168.3.141","qos":{},"speed_limit_mbps":1}`,
	} {
		var req DeviceUpdate
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatal(err)
		}
		if err := h.svc.UpdateDevice(context.Background(), req); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	var clear DeviceUpdate
	if err := json.Unmarshal([]byte(`{"ip":"192.168.3.141","qos":{}}`), &clear); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UpdateDevice(context.Background(), clear); err != nil {
		t.Fatal(err)
	}
	if len(fw.installed) != 0 || h.svc.state.DeviceAliases[ip] != "Tablet" || h.svc.state.DeviceRoutes[ip] != "direct" {
		t.Fatal("clearing QoS changed route/name")
	}
}

func TestQoSClashClassificationUsesActualLeafAndOriginalTuple(t *testing.T) {
	var snap trafficSnapshot
	if err := json.Unmarshal([]byte(`{"connections":[
 {"metadata":{"type":"tproxy/tproxy-in","sourceIP":"192.168.3.141","destinationIP":"8.8.8.8","network":"tcp","sourcePort":"23456","destinationPort":"443"},"chains":["direct"]},
 {"metadata":{"type":"tproxy/balance-aaa-0","sourceIP":"192.168.3.141","destinationIP":"1.1.1.1","network":"udp","sourcePort":"23457","destinationPort":"443"},"chains":["node-leaf","balance-selector","proxy"]}
 ]}`), &snap); err != nil {
		t.Fatal(err)
	}
	limits := map[string]netfilter.DeviceLimits{"192.168.3.141": netfilter.UniformLimits(1)}
	tags := map[string]string{"id": "node-leaf"}
	got := classifyQoSFlows(snap.Connections, limits, tags)
	want := []netfilter.QoSFlow{{SourceIP: "192.168.3.141", DestinationIP: "8.8.8.8", SourcePort: 23456, DestinationPort: 443, Network: "tcp", Direct: true}, {SourceIP: "192.168.3.141", DestinationIP: "1.1.1.1", SourcePort: 23457, DestinationPort: 443, Network: "udp"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("classification got %+v", got)
	}
	sample := snap.Connections[0]
	for _, change := range []func(*connectionSample){
		func(c *connectionSample) { c.Metadata.Type = "mixed/test" },
		func(c *connectionSample) { c.Metadata.SourceIP = "192.168.3.142" },
		func(c *connectionSample) { c.Metadata.DestinationIP = "" },
		func(c *connectionSample) { c.Metadata.SourcePort = "70000" },
		func(c *connectionSample) { c.Metadata.Network = "tcp; flush ruleset" },
		func(c *connectionSample) { c.Chains = []string{"unknown-leaf", "direct"} },
		func(c *connectionSample) { c.Chains = nil },
	} {
		c := sample
		change(&c)
		if len(classifyQoSFlows([]connectionSample{c}, limits, tags)) != 0 {
			t.Fatalf("bad sample classified: %+v", c)
		}
	}
}

func TestFakeDNSQoSRequestsKernelTupleRecovery(t *testing.T) {
	c := connectionSample{Metadata: connectionMetadata{SourceIP: "192.168.3.141", Host: "mapped.example", SourcePort: "2000", DestinationPort: "443", Type: "tproxy/tproxy-in", Network: "tcp"}, Chains: []string{"direct"}}
	limits := map[string]netfilter.DeviceLimits{"192.168.3.141": netfilter.UniformLimits(1)}
	if got := classifyQoSFlows([]connectionSample{c}, limits, nil); len(got) != 0 {
		t.Fatal("legacy mode accepted missing destination")
	}
	got := classifyQoSFlows([]connectionSample{c}, limits, nil, true)
	if len(got) != 1 || got[0].DestinationIP != "" || !got[0].Direct {
		t.Fatal("FakeDNS missing-IP flow lost actual class")
	}
	c.Metadata.Host = ""
	if got := classifyQoSFlows([]connectionSample{c}, limits, nil, true); len(got) != 0 {
		t.Fatal("malformed metadata eligible for FakeDNS recovery")
	}
}
