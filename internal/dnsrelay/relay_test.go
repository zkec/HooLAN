package dnsrelay

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

var query = []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}

func upstream(t *testing.T, rcode byte) (string, *atomic.Int32) {
	t.Helper()
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	tcp, e := net.Listen("tcp4", udp.LocalAddr().String())
	if e != nil {
		udp.Close()
		t.Fatal(e)
	}
	count := new(atomic.Int32)
	reply := func(q []byte) []byte {
		count.Add(1)
		r := append([]byte{}, q...)
		r[2] |= 0x80
		r[3] = 0x80 | rcode
		return r
	}
	go func() {
		b := make([]byte, 65535)
		for {
			n, p, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			udp.WriteToUDP(reply(b[:n]), p)
		}
	}()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				q, e := readFrame(c)
				if e == nil {
					_ = writeFrame(c, reply(q))
				}
			}()
		}
	}()
	t.Cleanup(func() { udp.Close(); tcp.Close() })
	return udp.LocalAddr().String(), count
}
func TestRelayOffFailureAndRecovery(t *testing.T) {
	direct, directCalls := upstream(t, 0)
	primary, primaryCalls := upstream(t, 0)
	failed, _ := upstream(t, 2)
	var mode atomic.Int32
	s := New(func(ip net.IP) Policy {
		p := Policy{Direct: direct}
		switch mode.Load() {
		case 1:
			p.Primary = primary
		case 2:
			p.Primary = failed
		case 3:
			p.Primary = "127.0.0.1:1"
		}
		return p
	})
	s.timeout = 100 * time.Millisecond
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	address := s.udp.LocalAddr().String()
	client := New(nil)
	for _, network := range []string{"udp", "tcp"} {
		for _, m := range []int32{0, 1, 2, 3, 1} {
			mode.Store(m)
			d, p := directCalls.Load(), primaryCalls.Load()
			r, e := client.exchange(context.Background(), network, address, query)
			if e != nil {
				t.Fatal(network, m, e)
			}
			if r[3]&15 != 0 {
				t.Fatal("no usable DNS answer")
			}
			if m == 1 {
				if primaryCalls.Load() != p+1 || directCalls.Load() != d {
					t.Fatal("healthy proxy must not leak to direct")
				}
			} else if directCalls.Load() != d+1 {
				t.Fatal("offline/failed DNS must fall back")
			}
		}
	}
}
func TestNoFallbackForNXDOMAINOrPolicyRejection(t *testing.T) {
	for _, code := range []byte{3, 5} {
		primary, _ := upstream(t, code)
		direct, calls := upstream(t, 0)
		s := New(func(net.IP) Policy { return Policy{Primary: primary, Direct: direct} })
		for _, network := range []string{"udp", "tcp"} {
			r := s.answer(context.Background(), network, nil, query)
			if r[3]&15 != code || calls.Load() != 0 {
				t.Fatal("DNS policy overridden")
			}
		}
	}
}
func TestListenerRebindFailurePreservesService(t *testing.T) {
	direct, _ := upstream(t, 0)
	s := New(func(net.IP) Policy { return Policy{Direct: direct} })
	if e := s.Listen("127.0.0.1:0"); e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	old := s.udp.LocalAddr().String()
	if e := s.Listen(direct); e == nil {
		t.Fatal("expected address conflict")
	}
	if _, e := s.exchange(context.Background(), "tcp", old, query); e != nil {
		t.Fatal(e)
	}
}
func TestWireValidationAndFailure(t *testing.T) {
	s := New(func(net.IP) Policy { return Policy{} })
	r := s.answer(context.Background(), "udp", nil, query)
	if r[3]&15 != 2 || binary.BigEndian.Uint16(r[4:6]) != 1 || len(r) != len(query) {
		t.Fatal("invalid SERVFAIL")
	}
	for i := 0; i < len(query); i++ {
		if questionEnd(query[:i]) != 0 {
			t.Fatal("accepted truncated request")
		}
	}
	bad := append([]byte{}, query...)
	bad[12] = 0xc0
	if questionEnd(bad) != 0 {
		t.Fatal("accepted invalid compressed query")
	}
}
