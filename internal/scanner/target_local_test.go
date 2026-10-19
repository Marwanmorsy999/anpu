package scanner

import (
	"strings"
	"testing"
)

// The local-network refusal must name a mechanism that actually works
// (ANPU_ALLOW_LOCAL_NETWORK=1), never a nonexistent flag.
func TestLocalNetworkRefusalNamesWorkingMechanism(t *testing.T) {
	old := AllowLocalNetwork
	AllowLocalNetwork = false
	defer func() { AllowLocalNetwork = old }()

	_, err := ValidateTarget("http://localhost:8080/")
	if err == nil {
		t.Fatal("localhost target must be refused by default")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ANPU_ALLOW_LOCAL_NETWORK=1") {
		t.Fatalf("refusal must name ANPU_ALLOW_LOCAL_NETWORK=1, got %q", msg)
	}
	if strings.Contains(msg, "--allow-local-network") {
		t.Fatalf("refusal must not name nonexistent --allow-local-network flag, got %q", msg)
	}

	_, err = ValidateTarget("http://127.0.0.1:8080/")
	if err == nil {
		t.Fatal("loopback IP target must be refused by default")
	}
	if strings.Contains(err.Error(), "--allow-local-network") {
		t.Fatalf("refusal must not name nonexistent --allow-local-network flag, got %q", err.Error())
	}

	// The named mechanism must actually lift the guard: AllowLocalNetwork
	// is read from ANPU_ALLOW_LOCAL_NETWORK at process start, so setting
	// it (as the env var does) must allow the same targets.
	AllowLocalNetwork = true
	if _, err := ValidateTarget("http://localhost:8080/"); err != nil {
		t.Fatalf("local-network override must allow localhost, got %v", err)
	}
	if _, err := ValidateTarget("http://127.0.0.1:8080/"); err != nil {
		t.Fatalf("local-network override must allow loopback IP, got %v", err)
	}
}
