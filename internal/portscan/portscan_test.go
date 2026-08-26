package portscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

func init() { scanner.AllowLocalNetwork = true }

func portscanContext(t *testing.T) *scanner.ScanContext {
	t.Helper()
	vt, err := scanner.ValidateTarget("http://127.0.0.1/")
	if err != nil { t.Fatalf("validate target: %v", err) }
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}}
}

func TestPortScan_Name(t *testing.T) {
	if got := New().Name(); got != "portscan" { t.Fatalf("got %q", got) }
}

func TestPortScan_DetectsInjectedOpenPort(t *testing.T) {
	s := New()
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ":8888") { return &fakeConn{}, nil }
		return nil, fmt.Errorf("closed")
	}
	res, err := s.Run(context.Background(), portscanContext(t))
	if err != nil { t.Fatal(err) }
	found := false
	for _, f := range res.Findings {
		if f.ID == "portscan-open-8888" { found = true; break }
	}
	if !found { t.Fatalf("expected open 8888 finding, got %+v", res.Findings) }
}

func TestPortScan_SanityProbeSuppressesResults(t *testing.T) {
	s := New()
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ":1") || strings.HasSuffix(address, ":9") { return &fakeConn{}, nil }
		return nil, fmt.Errorf("closed")
	}
	res, err := s.Run(context.Background(), portscanContext(t))
	if err != nil { t.Fatal(err) }
	if len(res.Findings) != 0 { t.Fatalf("expected suppressed findings, got %+v", res.Findings) }
	if len(res.Warnings) != 1 || !strings.HasPrefix(res.Warnings[0], "port scan unreliable:") {
		t.Fatalf("expected sanity-probe warning, got %v", res.Warnings)
	}
}

type fakeConn struct{}
func (*fakeConn) Read([]byte) (int, error) { return 0, nil }
func (*fakeConn) Write(p []byte) (int, error) { return len(p), nil }
func (*fakeConn) Close() error { return nil }
func (*fakeConn) LocalAddr() net.Addr { return fakeAddr("local") }
func (*fakeConn) RemoteAddr() net.Addr { return fakeAddr("remote") }
func (*fakeConn) SetDeadline(time.Time) error { return nil }
func (*fakeConn) SetReadDeadline(time.Time) error { return nil }
func (*fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string
func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string { return string(a) }
