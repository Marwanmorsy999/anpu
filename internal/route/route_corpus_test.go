package route

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// TestSampleRealCorpus pins route sampling against a real scan's
// endpoint corpus (testdata-corpus.json, 69 endpoints incl. probe
// artifacts): sampling must be deterministic and must preserve clean
// representative vectors like /search?q=anpu.
func TestSampleRealCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata-corpus.json")
	if err != nil {
		t.Skip("no corpus")
	}
	var doc struct {
		Endpoints []models.Endpoint `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	first := Sample(doc.Endpoints)
	second := Sample(doc.Endpoints)
	urls := func(eps []models.Endpoint) []string {
		var out []string
		for _, ep := range eps {
			out = append(out, ep.URL)
		}
		return out
	}
	if !reflect.DeepEqual(urls(first), urls(second)) {
		t.Fatal("sampling must be deterministic")
	}
	if len(first) >= len(doc.Endpoints) {
		t.Fatalf("expected reduction, got %d from %d", len(first), len(doc.Endpoints))
	}
	kept := map[string]bool{}
	for _, u := range urls(first) {
		kept[u] = true
	}
	if !kept["http://127.0.0.1:8901/search?q=anpu"] {
		t.Fatal("clean /search?q=anpu vector must survive sampling")
	}
}
