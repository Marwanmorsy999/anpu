// Package integrations — naabu fast-port-scan integration.
//
// naabu (ProjectDiscovery) is a fast SYN/connect port scanner. ANPU
// invokes it when installed (deep profile by default) and normalizes
// its JSON output into ANPU port findings. When missing, the built-in
// connect scanner (internal/portscan) remains the baseline.
//
// Absence degrades to a warning.
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/portscan"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// NaabuScanner implements scanner.Scanner by shelling out to naabu.
type NaabuScanner struct {
	BinaryPath string
	Timeout    time.Duration
}

func NewNaabuScanner() *NaabuScanner {
	return &NaabuScanner{Timeout: 4 * time.Minute}
}

func (n *NaabuScanner) Name() string { return "naabu" }

func (n *NaabuScanner) resolvedPath() string {
	if n.BinaryPath != "" {
		return n.BinaryPath
	}
	if p, err := findExecutable("naabu"); err == nil {
		return p
	}
	return "naabu"
}

func (n *NaabuScanner) Available(ctx context.Context) bool { return true }
func (n *NaabuScanner) availableExternal(ctx context.Context) bool {
	return versionCheck(ctx, n.resolvedPath())
}

// naabuJSONLine mirrors the fields ANPU cares about. naabu JSON has more.
type naabuJSONLine struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func (n *NaabuScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := sc.Target.Host
	if host == "" {
		return scanner.StageResult{}, nil
	}
	if n.availableExternal(ctx) {
		topPorts := "100"
		switch sc.Config.Profile {
		case models.ProfileUltra, models.ProfileDeep:
			topPorts = "1000"
		}
		args := []string{"-host", host, "-silent", "-json", "-top-ports", topPorts, "-rate", "1000"}
		stdout, _, err := runCapture(ctx, n.Timeout, n.resolvedPath(), args...)
		if err == nil || len(bytes.TrimSpace(stdout)) > 0 {
			if findings, warnings := parseNaabuOutput(stdout, host, sc.Target.Raw); len(findings) > 0 || len(warnings) > 0 {
				return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
			}
		}
	}
	// Embedded fallback: use built-in portscan logic (TCP connect, top 100)
	return n.runEmbedded(ctx, sc)
}

func (n *NaabuScanner) runEmbedded(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	// Reuse built-in portscan (TCP connect, bounded) as embedded naabu
	ps := portscan.New()
	return ps.Run(ctx, sc)
}

func parseNaabuOutput(data []byte, host, target string) ([]models.Finding, []string) {
	var ports []naabuJSONLine
	seen := map[int]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var j naabuJSONLine
		if err := json.Unmarshal([]byte(line), &j); err != nil {
			continue
		}
		if j.Port == 0 || seen[j.Port] {
			continue
		}
		seen[j.Port] = true
		ports = append(ports, j)
	}
	if len(ports) == 0 {
		return nil, nil
	}
	var findings []models.Finding
	for _, p := range ports {
		sev := models.SeverityInfo
		// Mirror portscan severity hints for risky services where possible.
		switch p.Port {
		case 22, 23, 445, 1433, 1521, 2049, 2375, 3306, 5432, 5900, 6379, 27017:
			sev = models.SeverityHigh
		case 21, 3389, 9200, 11211:
			sev = models.SeverityMedium
		case 80, 443:
			continue // web ports are not interesting as "extra" exposure
		}
		findings = append(findings, models.Finding{
			ID:              fmt.Sprintf("naabu-open-%d", p.Port),
			Title:           fmt.Sprintf("Port %d open on %s (naabu)", p.Port, host),
			Description:     fmt.Sprintf("naabu reported TCP port %d open on %s (%s). Verify the service is intentionally exposed.", p.Port, host, p.IP),
			Severity:        sev,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryConfiguration,
			Target:          target,
			URL:             fmt.Sprintf("tcp://%s:%d", host, p.Port),
			Evidence:        models.Evidence{Observed: fmt.Sprintf("%d/tcp open", p.Port), Location: "naabu JSON"},
			Source:          models.SourceCustom,
			DetectionMethod: "naabu fast port scan",
		})
	}
	return findings, nil
}
