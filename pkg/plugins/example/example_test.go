package example

import (
	"context"
	"net/http"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func TestGeneratorMetaHitAndMiss(t *testing.T) {
	fetch := func(body string) func(context.Context, string) (int, http.Header, []byte, error) {
		return func(context.Context, string) (int, http.Header, []byte, error) {
			return 200, nil, []byte(body), nil
		}
	}
	hit, err := GeneratorMeta{}.Run(context.Background(), "https://example.com",
		fetch(`<html><head><META NAME="generator" content="Blog 2.1"></head></html>`))
	if err != nil || len(hit) != 1 {
		t.Fatalf("expected 1 hit: %v %v", hit, err)
	}
	if hit[0].Source != models.SourcePlugin || hit[0].ID != "plugin-example-generator-meta" {
		t.Fatalf("attribution wrong: %+v", hit[0])
	}
	miss, err := GeneratorMeta{}.Run(context.Background(), "https://example.com",
		fetch(`<html><head><title>clean</title></head></html>`))
	if err != nil || len(miss) != 0 {
		t.Fatalf("expected no hit: %v %v", miss, err)
	}
}
