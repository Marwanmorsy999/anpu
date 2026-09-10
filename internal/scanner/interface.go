package scanner

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// StageResult is what every scan module returns: a set of findings plus
// any structured artifacts it wants to hand to the aggregate ScanSummary
// (technologies, endpoints). Not every module produces every field.
//
// Skipped is a quiet-skip channel: when set, the stage did not run
// (a runtime gate decided there was nothing useful to do) and the
// pipeline renders it as skipped with Skipped as the reason — no
// findings, no warning noise. It is mutually exclusive with Findings.
type StageResult struct {
	Findings     []models.Finding
	Technologies []models.Technology
	Endpoints    []models.Endpoint
	Subdomains   []string // live hostnames to expose to later stages
	Warnings     []string
	Skipped      string
}

// Vault is a thread-safe key-value store for extracted tokens/secrets.
// Adversarial modules use it to share CSRF tokens, nonces, or session
// identifiers across stateful multi-step probes without logging values.
type Vault struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewVault creates an empty Vault.
func NewVault() *Vault { return &Vault{data: make(map[string]string)} }

// Set stores a value (overwrites).
func (v *Vault) Set(key, value string) {
	if v == nil {
		return
	}
	v.mu.Lock()
	if v.data == nil {
		v.data = make(map[string]string)
	}
	v.data[key] = value
	v.mu.Unlock()
}

// Get retrieves a value.
func (v *Vault) Get(key string) (string, bool) {
	if v == nil || v.data == nil {
		return "", false
	}
	v.mu.RLock()
	val, ok := v.data[key]
	v.mu.RUnlock()
	return val, ok
}

// All returns a copy of all entries.
func (v *Vault) All() map[string]string {
	if v == nil || v.data == nil {
		return nil
	}
	v.mu.RLock()
	out := make(map[string]string, len(v.data))
	for k, val := range v.data {
		out[k] = val
	}
	v.mu.RUnlock()
	return out
}

// Extractor extracts named artifacts from an HTTP response (e.g., CSRF
// tokens, session cookies, nonces). Implementations must be stateless
// and safe for concurrent use.
type Extractor interface {
	Name() string
	Extract(resp *http.Response, body []byte) map[string]string
}

// Session holds stateful artifacts shared across pipeline stages for
// authorized adversarial testing: cookie jar for session continuity,
// vault for cross-step secrets, and extractors for token harvesting.
type Session struct {
	Jar        http.CookieJar
	Vault      *Vault
	Extractors []Extractor
}

// NewSession creates a stateful Session with an in-memory cookie jar
// and an empty Vault. Extractors start empty and can be appended by
// callers that need custom token harvesting.
func NewSession() *Session {
	jar, _ := NewCookieJar()
	return &Session{
		Jar:   jar,
		Vault: NewVault(),
	}
}

// NewCookieJar creates a simple in-memory CookieJar safe for tests.
func NewCookieJar() (http.CookieJar, error) {
	// Use standard library's cookiejar if available; fall back to a
	// minimal in-memory jar that satisfies the interface for tests.
	// We avoid importing net/http/cookiejar to keep the dependency
	// surface small; the jar below is sufficient for stateful probes.
	return &memJar{store: make(map[string][]*http.Cookie)}, nil
}

type memJar struct {
	mu    sync.Mutex
	store map[string][]*http.Cookie
}

func (j *memJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j == nil || u == nil {
		return
	}
	j.mu.Lock()
	j.store[u.Host] = append([]*http.Cookie(nil), cookies...)
	j.mu.Unlock()
}

func (j *memJar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil || u == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]*http.Cookie(nil), j.store[u.Host]...)
}

// ArtifactPool is a shared pool for arbitrary artifacts discovered
// during the scan (e.g., endpoints, JS-discovered URLs, auth tokens).
// It is safe for concurrent use and is exposed via ScanContext so
// adversarial modules can coordinate multi-step flows.
type ArtifactPool struct {
	mu   sync.Mutex
	pool map[string][]string
}

// NewArtifactPool creates an empty pool.
func NewArtifactPool() *ArtifactPool { return &ArtifactPool{pool: make(map[string][]string)} }

// Add appends artifacts under a key (deduplicated).
func (p *ArtifactPool) Add(key string, artifacts ...string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.pool == nil {
		p.pool = make(map[string][]string)
	}
	seen := make(map[string]bool, len(p.pool[key]))
	for _, v := range p.pool[key] {
		seen[v] = true
	}
	for _, a := range artifacts {
		if !seen[a] {
			p.pool[key] = append(p.pool[key], a)
			seen[a] = true
		}
	}
	p.mu.Unlock()
}

// Get returns a copy of artifacts for a key.
func (p *ArtifactPool) Get(key string) []string {
	if p == nil || p.pool == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.pool[key]...)
}

// All returns a copy of the entire pool.
func (p *ArtifactPool) All() map[string][]string {
	if p == nil || p.pool == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string][]string, len(p.pool))
	for k, v := range p.pool {
		out[k] = append(out[k], v...)
	}
	return out
}

// ScanContext is passed to every module and carries the shared state a
// stage may need (the validated target, discovered technologies so far,
// discovered endpoints so far, the resolved config).
type ScanContext struct {
	Target  *ValidatedTarget
	Config  models.ScanConfig
	Verbose bool

	// Auth is the credential context for this scan.  Stages that issue
	// HTTP requests should call Auth.RequestHeaders() and merge the
	// result into their requests so that authenticated surfaces are
	// reachable.  Credential values must never appear in findings or logs.
	Auth models.AuthContext

	// Session holds stateful cookies/tokens for adversarial multi-step flows.
	// It is non-nil for the entire pipeline (empty when not used) so stages
	// can share Jar/Vault without nil checks.
	Session *Session

	// ArtifactPool is a shared bucket for cross-stage artifacts (e.g.,
	// JS-discovered endpoints, extracted tokens). Stages that discover
	// candidates for later adversarial probes should Add() them here.
	ArtifactPool *ArtifactPool

	// Populated as the pipeline progresses so later stages (e.g. Nuclei)
	// can use earlier results (e.g. discovered endpoints).
	Technologies []models.Technology
	Endpoints    []models.Endpoint
	Subdomains   []string // live hostnames discovered by the subdomains stage

	// Ledger is the global per-tool request budget (Wave 4 item 151).
	// Stages with large-but-bounded matrices (hiddenparams, backupplus)
	// charge each request here and stop at their cap. Nil-safe: a nil
	// ledger means uncapped (tests, custom pipelines).
	Ledger *anpuhttp.Ledger
}

// Scanner is implemented by every pipeline stage: built-in analyzers
// (headers, cookies, TLS, technology, endpoint discovery) as well as
// external integrations (Nuclei, ZAP, and any future custom scanner).
//
// Keeping this interface narrow is what lets the core pipeline stay
// decoupled from any specific scanner implementation — new scanners are
// added by implementing this interface and registering them, with no
// changes to the orchestrator.
type Scanner interface {
	// Name is a short, stable identifier used in logs and the finding
	// Source field (e.g. "headers", "nuclei").
	Name() string

	// Available reports whether this scanner can run in the current
	// environment (e.g. whether an external binary like nuclei is
	// installed). Modules that are always available (built-in analyzers)
	// simply return true.
	Available(ctx context.Context) bool

	// Run executes the scan stage and returns its findings/artifacts.
	// Implementations must respect ctx cancellation/timeout and must
	// never treat target-controlled data as executable content (shell
	// commands, template directives, etc).
	Run(ctx context.Context, sc *ScanContext) (StageResult, error)
}
