package scanner

import "testing"

func TestValidateTarget_ValidHTTPS(t *testing.T) {
	vt, err := ValidateTarget("https://example.com/path")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if vt.Host != "example.com" {
		t.Errorf("expected host example.com, got %s", vt.Host)
	}
}

func TestValidateTarget_MissingScheme(t *testing.T) {
	if _, err := ValidateTarget("example.com"); err == nil {
		t.Error("expected error for missing scheme")
	}
}

func TestValidateTarget_InvalidScheme(t *testing.T) {
	if _, err := ValidateTarget("ftp://example.com"); err == nil {
		t.Error("expected error for non-http(s) scheme")
	}
}

func TestValidateTarget_EmptyURL(t *testing.T) {
	if _, err := ValidateTarget("   "); err == nil {
		t.Error("expected error for empty target")
	}
}

func TestValidateTarget_EmbeddedCredentials(t *testing.T) {
	if _, err := ValidateTarget("https://user:pass@example.com"); err == nil {
		t.Error("expected error for embedded credentials")
	}
}

func TestValidateTarget_RejectsLoopbackHostname(t *testing.T) {
	if _, err := ValidateTarget("http://localhost/"); err == nil {
		t.Error("expected error for localhost target")
	}
}

func TestValidateTarget_RejectsLoopbackIP(t *testing.T) {
	if _, err := ValidateTarget("http://127.0.0.1/"); err == nil {
		t.Error("expected error for loopback IP target")
	}
}

func TestValidateTarget_RejectsPrivateIP(t *testing.T) {
	cases := []string{
		"http://10.0.0.5/",
		"http://192.168.1.1/",
		"http://172.16.0.1/",
		"http://169.254.169.254/", // cloud metadata
	}
	for _, c := range cases {
		if _, err := ValidateTarget(c); err == nil {
			t.Errorf("expected error for private/link-local target %s", c)
		}
	}
}

func TestValidateTarget_AllowLocalNetworkOverride(t *testing.T) {
	orig := AllowLocalNetwork
	AllowLocalNetwork = true
	defer func() { AllowLocalNetwork = orig }()

	if _, err := ValidateTarget("http://127.0.0.1:8080/"); err != nil {
		t.Errorf("expected no error with AllowLocalNetwork=true, got %v", err)
	}
}

func TestValidateTarget_PublicIPAllowed(t *testing.T) {
	// 8.8.8.8 is a well-known public IP (Google DNS) — used only to
	// verify the validator doesn't reject public addresses, no network
	// request is made here.
	if _, err := ValidateTarget("http://8.8.8.8/"); err != nil {
		t.Errorf("expected no error for public IP, got %v", err)
	}
}
