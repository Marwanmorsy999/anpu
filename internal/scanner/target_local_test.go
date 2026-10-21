package scanner

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// childEnvMarker is set on the re-executed test binary that verifies the
// environment-variable mechanism end to end.
const childEnvMarker = "ANPU_LOCALNET_GUARD_TEST_CHILD"

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
	if !strings.Contains(err.Error(), "ANPU_ALLOW_LOCAL_NETWORK=1") {
		t.Fatalf("loopback IP refusal must name ANPU_ALLOW_LOCAL_NETWORK=1, got %q", err.Error())
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

// TestAllowLocalNetworkEnvVarIsTheNamedMechanism proves that the
// ANPU_ALLOW_LOCAL_NETWORK=1 named in both refusal messages is a real
// mechanism and not just a string in an error message: a child process
// started with that environment variable must have the guard lifted and
// must accept the very targets that are refused by default.
func TestAllowLocalNetworkEnvVarIsTheNamedMechanism(t *testing.T) {
	if os.Getenv(childEnvMarker) == "1" {
		if !AllowLocalNetwork {
			t.Fatal("ANPU_ALLOW_LOCAL_NETWORK=1 must enable the local-network override")
		}
		for _, target := range []string{"http://localhost:8080/", "http://127.0.0.1:8080/"} {
			if _, err := ValidateTarget(target); err != nil {
				t.Fatalf("target %q must be allowed when ANPU_ALLOW_LOCAL_NETWORK=1, got %v", target, err)
			}
		}
		return
	}

	// Guard against a vacuous pass: the child must really have run with
	// the environment variable set.
	cmd := exec.Command(os.Args[0], "-test.run=^TestAllowLocalNetworkEnvVarIsTheNamedMechanism$")
	cmd.Env = append(os.Environ(), childEnvMarker+"=1", "ANPU_ALLOW_LOCAL_NETWORK=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process with ANPU_ALLOW_LOCAL_NETWORK=1 failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("child test output must show PASS, got:\n%s", out)
	}
}
