package scanner

import (
	"context"

	"github.com/anpu-project/anpu/pkg/models"
)

// StageResult is what every scan module returns: a set of findings plus
// any structured artifacts it wants to hand to the aggregate ScanSummary
// (technologies, endpoints). Not every module produces every field.
type StageResult struct {
	Findings     []models.Finding
	Technologies []models.Technology
	Endpoints    []models.Endpoint
	Warnings     []string
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

	// Populated as the pipeline progresses so later stages (e.g. Nuclei)
	// can use earlier results (e.g. discovered endpoints).
	Technologies []models.Technology
	Endpoints    []models.Endpoint
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
