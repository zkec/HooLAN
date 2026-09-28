// Package dnsrelay keeps the gateway's DNS listener available independently of
// its proxy process. It forwards wire messages without caching or rewriting them.
package dnsrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Policy is evaluated for every request. Empty Primary means direct-only.
// Fallback is used on transport failure or SERVFAIL, never on NXDOMAIN/REFUSED.
type Policy struct{ Primary, Direct string }
type Server struct {
	mu      sync.Mutex
	udp     *net.UDPConn
	tcp     net.Listener
	cancel  context.CancelFunc
	address string
	policy  func(net.IP) Policy
	slots   chan struct{}
	wg      sync.WaitGroup
	timeout time.Duration
}

func New(policy func(net.IP) Policy) *Server {
	return &Server{policy: policy, slots: make(chan struct{}, 128), timeout: 2 * time.Second}
}

// Listen binds both transports before releasing the old listeners. A failed
// address change leaves the existing listener intact. Call Close at shutdown.
func (s *Server) Listen(address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.address == address && s.udp != nil {
		return nil
	}
	a, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp4", a)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		return err
	}
	if s.cancel != nil {
		s.cancel()
		s.udp.Close()
		s.tcp.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.udp, s.tcp, s.cancel, s.address = udp, tcp, cancel, address
	s.wg.Add(2)
	go s.serveUDP(ctx, udp)
	go s.serveTCP(ctx, tcp)
	return nil
}
func (s *Server) Close() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		s.udp.Close()
		s.tcp.Close()
		s.cancel = nil
		s.udp = nil
		s.address = ""
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Server) serveUDP(ctx context.Context, c *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, peer, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if questionEnd(buf[:n]) == 0 || buf[2]&0x80 != 0 {
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			response := s.answer(ctx, "udp", peer.IP, q)
			if ctx.Err() == nil {
				_, _ = c.WriteToUDP(response, peer)
			}
		}()
	}
}
func (s *Server) serveTCP(ctx context.Context, l net.Listener) {
	defer s.wg.Done()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case s.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			defer c.Close()
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-ctx.Done():
					c.Close()
				case <-done:
				}
			}()
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readFrame(c)
				if err != nil || questionEnd(q) == 0 || q[2]&0x80 != 0 {
					return
				}
				response := s.answer(ctx, "tcp", c.RemoteAddr().(*net.TCPAddr).IP, q)
				if err = writeFrame(c, response); err != nil {
					return
				}
			}
		}()
	}
}
func (s *Server) answer(ctx context.Context, network string, ip net.IP, q []byte) []byte {
	p := s.policy(ip)
	if p.Primary != "" {
		r, err := s.exchange(ctx, network, p.Primary, q)
		if err == nil && r[3]&15 != 2 {
			return r
		}
	}
	if p.Direct != "" && ctx.Err() == nil {
		if r, err := s.exchange(ctx, network, p.Direct, q); err == nil {
			return r
		}
	}
	// Only echo the question: copied answer/additional counts would create a
	// malformed response or repeat EDNS metadata with incorrect lengths.
	end := questionEnd(q)
	if end == 0 {
		return nil
	}
	r := append([]byte(nil), q[:end]...)
	r[2] = (q[2] & 0x79) | 0x80
	r[3] = 0x82
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	return r
}
func (s *Server) exchange(ctx context.Context, network, address string, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	var r []byte
	if network == "tcp" {
		if err = writeFrame(c, q); err == nil {
			r, err = readFrame(c)
		}
	} else {
		if _, err = c.Write(q); err == nil {
			r = make([]byte, 65535)
			var n int
			n, err = c.Read(r)
			r = r[:n]
		}
	}
	if err != nil {
		return nil, err
	}
	qe, re := questionEnd(q), questionEnd(r)
	if re == 0 || qe != re || !bytes.Equal(q[:2], r[:2]) || r[2]&0x80 == 0 || q[2]&0x78 != r[2]&0x78 || !bytes.Equal(q[12:qe], r[12:re]) {
		return nil, errors.New("invalid DNS response")
	}
	return r, nil
}
func readFrame(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 {
		return nil, errors.New("short DNS message")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeFrame(w io.Writer, b []byte) error {
	if len(b) < 12 || len(b) > 65535 {
		return errors.New("invalid DNS length")
	}
	frame := make([]byte, len(b)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(b)))
	copy(frame[2:], b)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
func questionEnd(b []byte) int {
	if len(b) < 12 || binary.BigEndian.Uint16(b[4:6]) != 1 {
		return 0
	}
	i := 12
	for labels := 0; labels < 128; labels++ {
		if i >= len(b) {
			return 0
		}
		n := int(b[i])
		i++
		if n == 0 {
			if i+4 <= len(b) {
				return i + 4
			}
			return 0
		}
		if n > 63 || i+n > len(b) {
			return 0
		}
		i += n
	}
	return 0
}
