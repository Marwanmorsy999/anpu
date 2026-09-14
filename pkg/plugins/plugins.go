// Package plugins is ANPU's stable extension SDK: declarative YAML
// checks and Go plugins that run user-defined detections through the
// same guarded fetching as built-in engines.
//
// Safety contract (enforced by construction, not convention): plugins
// never touch the network directly. The host passes a FetchFunc that
// carries ANPU's SSRF, local-network, timeout, and redirect guards, so
// a plugin cannot probe anything the CLI itself would refuse. The only
// imports here are pkg/models and the standard library, keeping the
// public SDK free of internal dependencies and import cycles.
package plugins

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// FetchFunc fetches one URL under the host's safety guards and returns
// the status code, headers, and (bounded) body. Implemented by the host
// (cmd/anpu); plugins only ever see this signature.
type FetchFunc func(ctx context.Context, url string) (status int, header http.Header, body []byte, err error)

// Plugin is a compiled-in custom detection. Implement Name,
// Description, and Run; register with Register (usually in init or an
// explicit wiring site, never inside the scan pipeline); execute with
// `anpu plugin run --name`.
type Plugin interface {
	// Name is the stable registry key (lowercase, hyphenated).
	Name() string
	// Description is one human line shown by `anpu plugin list`.
	Description() string
	// Run executes the detection against target using fetch for every
	// request. Return findings with Source models.SourcePlugin; IDs
	// must be deterministic for the same observation.
	Run(ctx context.Context, target string, fetch FetchFunc) ([]models.Finding, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Plugin{}
)

// Register adds a plugin to the process registry. It panics on empty
// or duplicate names: registration is programmer wiring, and silent
// shadowing would misattribute findings.
func Register(p Plugin) {
	if p == nil || p.Name() == "" {
		panic("plugins: Register called with nil or unnamed plugin")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[p.Name()]; dup {
		panic("plugins: duplicate plugin name " + p.Name())
	}
	registry[p.Name()] = p
}

// Lookup returns the registered plugin or false.
func Lookup(name string) (Plugin, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// List returns registered plugin names, sorted.
func List() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ResetRegistry clears all registrations. Test-only: production code
// must never call it (registrations are process wiring).
func ResetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = map[string]Plugin{}
}

// pluginError wraps plugin failures with the plugin name for triage.
type pluginError struct {
	name string
	err  error
}

func (e *pluginError) Error() string { return fmt.Sprintf("plugin %q: %v", e.name, e.err) }
func (e *pluginError) Unwrap() error { return e.err }

// RunNamed executes a registered plugin by name.
func RunNamed(ctx context.Context, name, target string, fetch FetchFunc) ([]models.Finding, error) {
	p, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown plugin %q (see `anpu plugin list`)", name)
	}
	findings, err := p.Run(ctx, target, fetch)
	if err != nil {
		return nil, &pluginError{name: name, err: err}
	}
	return findings, nil
}
