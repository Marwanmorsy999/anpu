package active

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/anpu-project/anpu/internal/fpmatch"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
)

// soft404.go — active soft-404 detection (mirrors dirs.go:122,176).
//
// Dirs uses a random baseline path to learn what a missing page looks
// like (status, body hash, word-set similarity). Active needs the same
// primitive: adversarial probes that hit non-existent parameter values
// should not be mistaken for real findings (e.g., 200 with the same
// catch-all template). The detector is intentionally lightweight — two
// GETs at construction, then hash/similarity checks per probe.

// soft404Detector holds the baseline for one scan target.
type soft404Detector struct {
	baselineStatus int
	baselineHash   [32]byte
	baselineSize   int
	baselineWords  map[string]struct{}
	catchAll       bool
	rootHash       [32]byte
	rootWords      map[string]struct{}
	rootHasBody    bool
}

// newSoft404Detector fetches two random baselines and the root to build
// a detector. Fail-open: on error it returns nil (no filtering).
func newSoft404Detector(ctx context.Context, client *anpuhttp.Client, base string) *soft404Detector {
	// Strip query/fragment so baselines probe random paths — not random
	// values of the target's own parameters (which would render the
	// endpoint template and suppress it as its own baseline).
	base = strings.TrimRight(stripQuery(base), "/")
	// Baseline A.
	respA, err := client.Get(ctx, base+"/"+randHexActive(16))
	if err != nil || respA == nil {
		return nil
	}
	hashA := normHashActive(respA.Body)
	sizeA := len(respA.Body)
	wordsA := wordSetActive(respA.Body)

	// Baseline B — check if catch-all serves same template.
	// Baseline words are ALWAYS retained (not only for catch-all) so
	// similarity gating works in every mode — see isSoft404.
	catchAll := false
	wordsBase := wordsA
	if respB, err := client.Get(ctx, base+"/"+randHexActive(16)); err == nil && respB != nil && respB.StatusCode == respA.StatusCode {
		wB := wordSetActive(respB.Body)
		if similarityActive(wordsA, wB) >= fpmatch.CatchAllDetect {
			catchAll = true
		}
	}

	// Root for app-shell suppression.
	var rootHash [32]byte
	var rootWords map[string]struct{}
	rootHasBody := false
	if rootResp, err := client.Get(ctx, base+"/"); err == nil && rootResp != nil && len(rootResp.Body) > 0 {
		rootWords = wordSetActive(rootResp.Body)
		rootHash = normHashActive(rootResp.Body)
		rootHasBody = true
	}

	return &soft404Detector{
		baselineStatus: respA.StatusCode,
		baselineHash:   hashA,
		baselineSize:   sizeA,
		baselineWords:  wordsBase,
		catchAll:       catchAll,
		rootHash:       rootHash,
		rootWords:      rootWords,
		rootHasBody:    rootHasBody,
	}
}

// isSoft404 reports whether resp looks like the soft-404 baseline or
// the application shell: exact normalized-hash match, or word-set
// similarity at/above threshold against either template.
func (d *soft404Detector) isSoft404(resp *anpuhttp.Response) bool {
	if d == nil || resp == nil {
		return false
	}
	if normHashActive(resp.Body) == d.baselineHash {
		return true
	}
	if d.rootHasBody && normHashActive(resp.Body) == d.rootHash {
		return true
	}
	probeWords := wordSetActive(resp.Body)
	if d.baselineWords != nil && similarityActive(probeWords, d.baselineWords) >= fpmatch.ShellMatch {
		return true
	}
	if len(d.rootWords) > 0 && similarityActive(probeWords, d.rootWords) >= fpmatch.ShellMatch {
		return true
	}
	return false
}

// soft404Score returns the best template similarity (0-1) for gating.
// Exact hash matches score 1.0; otherwise the max Jaccard similarity
// against baseline and root templates. Used for the >0.85 threshold in
// active/scanner.go — works in every mode, not just catch-all.
func (d *soft404Detector) soft404Score(resp *anpuhttp.Response) float64 {
	if d == nil || resp == nil {
		return 0
	}
	if normHashActive(resp.Body) == d.baselineHash {
		return 1.0
	}
	if d.rootHasBody && normHashActive(resp.Body) == d.rootHash {
		return 1.0
	}
	probeWords := wordSetActive(resp.Body)
	best := 0.0
	if d.baselineWords != nil {
		if s := similarityActive(probeWords, d.baselineWords); s > best {
			best = s
		}
	}
	if len(d.rootWords) > 0 {
		if s := similarityActive(probeWords, d.rootWords); s > best {
			best = s
		}
	}
	return best
}

// Helpers mirrored from dirs.go (local copies to avoid import cycle).

func randHexActive(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString(buf)
	}
	return hex.EncodeToString(buf)
}

var highEntropyReActive = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)

func normalizeBodyActive(body []byte) []byte {
	const cap = 100 << 10
	if len(body) > cap {
		body = body[:cap]
	}
	return highEntropyReActive.ReplaceAll(body, nil)
}

func normHashActive(body []byte) [32]byte {
	return sha256.Sum256(normalizeBodyActive(body))
}

var wordReActive = regexp.MustCompile(`[a-z]{3,}`)

func wordSetActive(body []byte) map[string]struct{} {
	const cap = 100 << 10
	if len(body) > cap {
		body = body[:cap]
	}
	words := wordReActive.FindAllString(strings.ToLower(string(normalizeBodyActive(body))), -1)
	set := make(map[string]struct{}, len(words))
	for _, w := range words {
		set[w] = struct{}{}
	}
	return set
}

func similarityActive(a, b map[string]struct{}) float64 {
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

// isHTMLorJSON reports whether Content-Type looks like html or json.
// Used for the active gate: only 200 + html/json are worth probing.
func isHTMLorJSON(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") || strings.Contains(ct, "application/xhtml+xml")
}
