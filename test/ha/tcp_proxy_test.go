package ha_test

import (
	"io"
	"net"
	"sync"
	"testing"
)

type tcpProxy struct {
	listener net.Listener
	upstream string

	mu      sync.Mutex
	enabled bool
	active  map[net.Conn]struct{}
}

func newTCPProxy(t *testing.T, listen, upstream string) *tcpProxy {
	t.Helper()
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &tcpProxy{
		listener: listener, upstream: upstream,
		enabled: true, active: make(map[net.Conn]struct{}),
	}
	go proxy.serve()
	t.Cleanup(proxy.Close)
	return proxy
}

func (p *tcpProxy) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
	if enabled {
		return
	}
	for conn := range p.active {
		_ = conn.Close()
	}
	clear(p.active)
}

func (p *tcpProxy) Close() {
	p.SetEnabled(false)
	_ = p.listener.Close()
}

func (p *tcpProxy) serve() {
	for {
		downstream, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.forward(downstream)
	}
}

func (p *tcpProxy) forward(downstream net.Conn) {
	p.mu.Lock()
	if !p.enabled {
		p.mu.Unlock()
		_ = downstream.Close()
		return
	}
	upstream, err := net.Dial("tcp", p.upstream)
	if err != nil {
		p.mu.Unlock()
		_ = downstream.Close()
		return
	}
	p.active[downstream] = struct{}{}
	p.active[upstream] = struct{}{}
	p.mu.Unlock()
	defer p.release(downstream, upstream)
	go func() {
		_, _ = io.Copy(upstream, downstream)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(downstream, upstream)
}

func (p *tcpProxy) release(conns ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range conns {
		delete(p.active, conn)
		_ = conn.Close()
	}
}
