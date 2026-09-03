package notify

import (
	"encoding/json"
	"testing"

	"github.com/anpu-project/anpu/internal/diff"
)

func TestParseOn(t *testing.T) {
	cases := []struct {
		in      string
		want    On
		wantErr bool
	}{
		{"always", OnAlways, false},
		{"change", OnChange, false},
		{"finding", OnFinding, false},
		{"ALWAYS", OnAlways, false},
		{"", OnChange, false},
		{"never", "", true},
		{"bad", "", true},
	}
	for _, tc := range cases {
		got, err := ParseOn(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseOn(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseOn(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseOn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShouldNotify(t *testing.T) {
	empty := &diff.Result{}
	withNew := &diff.Result{FindingsAdded: 1}
	withChanged := &diff.Result{FindingsChanged: 1}
	withEndpoints := &diff.Result{EndpointsAdded: 2}

	cases := []struct {
		result *diff.Result
		on     On
		want   bool
	}{
		{empty, OnAlways, true},
		{withNew, OnAlways, true},
		{empty, OnChange, false},
		{withNew, OnChange, true},
		{withChanged, OnChange, true},
		{withEndpoints, OnChange, true},
		{empty, OnFinding, false},
		{withNew, OnFinding, true},
		{withChanged, OnFinding, false}, // changed but not added
		{withEndpoints, OnFinding, false},
	}
	for _, tc := range cases {
		got := ShouldNotify(tc.result, tc.on)
		if got != tc.want {
			t.Errorf("ShouldNotify(findings_added=%d, on=%q) = %v, want %v",
				tc.result.FindingsAdded, tc.on, got, tc.want)
		}
	}
}

func TestGenericPayload(t *testing.T) {
	result := &diff.Result{Target: "https://example.com", FindingsAdded: 1}
	data, err := genericPayload(result)
	if err != nil {
		t.Fatalf("genericPayload: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if envelope["source"] != "anpu-watch" {
		t.Errorf("source = %v, want anpu-watch", envelope["source"])
	}
	if envelope["result"] == nil {
		t.Error("result field missing")
	}
}

func TestSlackPayload(t *testing.T) {
	result := &diff.Result{
		Target:        "https://example.com",
		RiskBefore:    3.0,
		RiskAfter:     5.0,
		RiskDelta:     2.0,
		FindingsAdded: 1,
	}
	data, err := slackPayload(result)
	if err != nil {
		t.Fatalf("slackPayload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["blocks"] == nil {
		t.Error("blocks field missing from Slack payload")
	}
}
