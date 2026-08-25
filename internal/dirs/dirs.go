// Package dirs probes a built-in list of commonly-sensitive paths on the
// target (/.env, /.git/config, /backup.zip, /phpinfo.php, ...) and
// reports anything that actually exists. It is the lightweight,
// dependency-free equivalent of gobuster/dirsearch's "common list" mode:
//
//   - GET-only, bounded concurrency, small responses
//   - soft-404 detection via a random baseline path so misconfigured
//     catch-all routers don't flood the report
//   - severity is path-class aware: exposed .env/.git/backups are high;
//     merely existing admin/login pages are informational
package dirs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for sensitive-path discovery.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (d *Scanner) Name() string { return "dirs" }

func (d *Scanner) Available(ctx context.Context) bool { return true }

type probe struct {
	Path  string
	Class severityClass
	Note  string
}

type severityClass int

const (
	classCriticalExposure severityClass = iota
	classServerInfo
	classAdmin
	classInteresting
)

var wordlist = []probe{
	{"/.env", classCriticalExposure, "environment file (may contain secrets)"},
	{"/.env.local", classCriticalExposure, "local environment file"},
	{"/.env.production", classCriticalExposure, "production environment file"},
	{"/.git/config", classCriticalExposure, "git repository metadata"},
	{"/.git/HEAD", classCriticalExposure, "git repository metadata"},
	{"/.svn/entries", classCriticalExposure, "svn repository metadata"},
	{"/.DS_Store", classInteresting, "macOS directory listing artifact"},
	{"/backup.zip", classCriticalExposure, "backup archive"},
	{"/backup.tar.gz", classCriticalExposure, "backup archive"},
	{"/backup.sql", classCriticalExposure, "database dump"},
	{"/db.sql", classCriticalExposure, "database dump"},
	{"/dump.sql", classCriticalExposure, "database dump"},
	{"/database.yml", classCriticalExposure, "database configuration"},
	{"/config.php.bak", classCriticalExposure, "configuration backup"},
	{"/wp-config.php.bak", classCriticalExposure, "WordPress configuration backup"},
	{"/settings.py", classCriticalExposure, "Django settings"},
	{"/credentials.json", classCriticalExposure, "credentials file"},
	{"/service-account.json", classCriticalExposure, "cloud service account key"},
	{"/.aws/credentials", classCriticalExposure, "AWS credentials"},
	{"/id_rsa", classCriticalExposure, "private SSH key"},
	{"/composer.lock", classInteresting, "PHP dependency manifest"},
	{"/package.json", classInteresting, "Node dependency manifest"},
	{"/web.config", classInteresting, "IIS configuration"},
	{"/crossdomain.xml", classInteresting, "legacy Flash policy"},
	{"/phpinfo.php", classServerInfo, "PHP information page"},
	{"/info.php", classServerInfo, "PHP information page"},
	{"/test.php", classServerInfo, "test PHP page"},
	{"/server-status", classServerInfo, "Apache status page"},
	{"/server-info", classServerInfo, "Apache info page"},
	{"/.well-known/security.txt", classInteresting, "security contact file"},
	{"/security.txt", classInteresting, "security contact file"},
	{"/admin/", classAdmin, "admin panel"},
	{"/administrator/", classAdmin, "admin panel"},
	{"/wp-admin/", classAdmin, "WordPress admin"},
	{"/manager/html", classAdmin, "Tomcat manager"},
	{"/phpmyadmin/", classAdmin, "phpMyAdmin"},
	{"/adminer.php", classAdmin, "Adminer DB UI"},
	{"/jenkins/", classAdmin, "Jenkins CI"},
	{"/actuator/", classServerInfo, "Spring Boot actuator"},
	{"/actuator/env", classCriticalExposure, "Spring env endpoint"},
	{"/debug/vars", classServerInfo, "Go expvar endpoint"},
	{"/metrics", classServerInfo, "Prometheus metrics"},
	{"/graphql", classInteresting, "GraphQL endpoint"},
	{"/api/", classInteresting, "API root"},
	{"/api/v1/", classInteresting, "API v1 root"},
	{"/swagger.json", classInteresting, "OpenAPI spec"},
	{"/openapi.json", classInteresting, "OpenAPI spec"},
	{"/swagger-ui/", classInteresting, "Swagger UI"},
	{"/robots.txt", classInteresting, "crawler rules"},
	{"/sitemap.xml", classInteresting, "sitemap"},
	{"/cgi-bin/", classServerInfo, "CGI directory"},
	{"/uploads/", classInteresting, "uploads directory"},
	{"/files/", classInteresting, "files directory"},
	{"/temp/", classInteresting, "temp directory"},
	{"/tmp/", classInteresting, "temp directory"},
	{"/logs/", classInteresting, "logs directory"},
	{"/error.log", classInteresting, "error log"},
	{"/access.log", classInteresting, "access log"},
	{"/.htaccess", classInteresting, "Apache config"},
	{"/.htpasswd", classCriticalExposure, "Apache password file"},
	{"/WEB-INF/web.xml", classCriticalExposure, "Java web descriptor"},
}

func (d *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	base := strings.TrimRight(sc.Target.Raw, "/")

	baseA, err := d.client.Get(ctx, base+"/"+randHex(16))
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("fetching soft-404 baseline: %w", err)
	}
	notFoundStatus := baseA.StatusCode
	notFoundHash := sha256.Sum256(baseA.Body)
	notFoundSize := len(baseA.Body)
	var notFoundWords map[string]struct{}
	catchAll := false

	baseB, err := d.client.Get(ctx, base+"/"+randHex(16))
	if err == nil && baseB.StatusCode == baseA.StatusCode {
		wA := wordSet(baseA.Body)
		wB := wordSet(baseB.Body)
		if similarity(wA, wB) >= 0.85 {
			catchAll = true
			notFoundWords = wA
		}
	}

	rootResp, err := d.client.Get(ctx, base+"/")
	rootWords := map[string]struct{}{}
	if err == nil && rootResp != nil && len(rootResp.Body) > 0 {
		rootWords = wordSet(rootResp.Body)
	}

	type hit struct {
		p    probe
		resp *anpuhttp.Response
	}
	var (
		mu   sync.Mutex
		hits []hit
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 8)
	)

	for _, p := range wordlist {
		wg.Add(1)
		go func(p probe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			resp, err := d.client.Get(cctx, base+p.Path)
			if err != nil || resp == nil {
				return
			}

			// HTTP 2xx is positive evidence that the requested resource
			// is reachable. 4xx/5xx responses are not evidence that the
			// sensitive path exists: WAFs, CDNs and application routers
			// commonly return generic 401/403/404/406 responses for both
			// real and nonexistent paths. In particular, a generic 403
			// must never be reported as "file exists" without independent
			// corroboration.
			if !recordableStatus(resp.StatusCode) {
				return
			}

			if resp.StatusCode == notFoundStatus {
				if catchAll {
					if similarity(wordSet(resp.Body), notFoundWords) >= 0.85 {
						return
					}
				} else if len(resp.Body) == notFoundSize && sha256.Sum256(resp.Body) == notFoundHash {
					return
				} else if similarity(wordSet(resp.Body), wordSet(baseA.Body)) >= 0.90 {
					return
				}
			}

			if len(rootWords) > 0 &&
				similarity(wordSet(resp.Body), rootWords) >= 0.90 {
				return
			}

			mu.Lock()
			hits = append(hits, hit{p, resp})
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	var findings []models.Finding
	for _, h := range hits {
		sev, conf := classify(h.p.Class)
		findings = append(findings, models.Finding{
			ID:          "dirs-exposed-" + slug(h.p.Path),
			Title:       fmt.Sprintf("%s returned HTTP %d", h.p.Path, h.resp.StatusCode),
			Description: exposedDescription(h.p.Path, h.resp.StatusCode, h.p.Note),
			Severity:    sev,
			Confidence:  conf,
			Category:    models.CategoryExposure,
			CWE:         cweFor(h.p.Class),
			Target:      sc.Target.Raw,
			URL:         base + h.p.Path,
			Evidence: models.Evidence{
				Observed:       fmt.Sprintf("HTTP %d, %d bytes%s", h.resp.StatusCode, len(h.resp.Body), contentTypeSuffix(h.resp.Header.Get("Content-Type"))),
				RequestSummary: "GET " + h.p.Path,
				Location:       "HTTP response",
			},
			Source:          models.SourceCustom,
			DetectionMethod: "sensitive-path probing with soft-404 baseline",
			Impact:          impactFor(h.p.Class),
			Remediation:     remediationFor(h.p.Class),
		})
	}

	return scanner.StageResult{Findings: findings}, nil
}

// recordableStatus returns true only when the probe received a successful
// 2xx response. Denials and error responses are inconclusive because a WAF,
// CDN or application router can emit the same status for existing and missing
// resources.
func recordableStatus(status int) bool {
	return status >= 200 && status < 300
}

func exposedDescription(path string, status int, note string) string {
	return fmt.Sprintf("The path %s returned HTTP %d and was therefore reachable. It appears to be %s. Paths like this are routinely probed by attackers; exposure may disclose configuration, credentials, or internal structure.", path, status, article(note))
}

func classify(c severityClass) (models.Severity, models.Confidence) {
	switch c {
	case classCriticalExposure:
		return models.SeverityHigh, models.ConfidenceHigh
	case classServerInfo:
		return models.SeverityMedium, models.ConfidenceMedium
	case classAdmin:
		return models.SeverityLow, models.ConfidenceLow
	default:
		return models.SeverityInfo, models.ConfidenceMedium
	}
}

func cweFor(c severityClass) string {
	switch c {
	case classCriticalExposure:
		return "CWE-538"
	case classServerInfo:
		return "CWE-200"
	case classAdmin:
		return "CWE-1236"
	default:
		return ""
	}
}

func impactFor(c severityClass) string {
	switch c {
	case classCriticalExposure:
		return "Configuration and credential files at publicly-reachable paths are a direct path to full compromise (source disclosure, database access, cloud account takeover)."
	case classServerInfo:
		return "Detailed server/debug output helps attackers map versions, frameworks, and internal state before exploitation."
	case classAdmin:
		return "Discoverable admin surfaces concentrate attacker attention; they must enforce strong authentication and rate limiting."
	default:
		return "Reveals implementation details that narrow the attacker's search space."
	}
}

func remediationFor(c severityClass) string {
	switch c {
	case classCriticalExposure:
		return "Remove the file from the deployed artifact and block access to it at the web-server/reverse-proxy layer (e.g. deny /.env, /.git, *.sql, *.bak). Rotate any secret that was reachable."
	case classServerInfo:
		return "Disable debug/status endpoints in production or gate them behind authentication and network restrictions."
	case classAdmin:
		return "Ensure the panel requires authentication and MFA; consider IP allow-listing or VPN-only access."
	default:
		return "Confirm the resource is intended to be public; otherwise restrict it."
	}
}

func article(s string) string {
	if s == "" {
		return "present"
	}
	switch s[0] {
	case 'a', 'e', 'i', 'o', 'u':
		return "an " + s
	}
	return "a " + s
}

func contentTypeSuffix(ct string) string {
	if ct == "" {
		return ""
	}
	return ", content-type: " + strings.SplitN(ct, ";", 2)[0]
}

func slug(p string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(p) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString(buf)
	}
	return hex.EncodeToString(buf)
}

func wordSet(body []byte) map[string]struct{} {
	const cap = 100 << 10
	if len(body) > cap {
		body = body[:cap]
	}
	words := wordRe.FindAllString(strings.ToLower(string(body)), -1)
	set := make(map[string]struct{}, len(words))
	for _, w := range words {
		set[w] = struct{}{}
	}
	return set
}

var wordRe = regexp.MustCompile(`[a-z]{3,}`)

func similarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	small, large := a, b
	if len(small) > len(large) {
		small, large = large, small
	}
	inter := 0
	for w := range small {
		if _, ok := large[w]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}
