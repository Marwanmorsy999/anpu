package headers

import (
	"context"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
)

// VerifyAbsent refetches targetRaw and reports which posture headers are
// absent right now. It powers `anpu verify` for headers-posture findings:
// the same rows function feeds both scan and verify, so a CONFIRMED
// verdict means the checklist reproduces with fresh controls.
func VerifyAbsent(ctx context.Context, client *anpuhttp.Client, targetRaw string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := client.Get(cctx, targetRaw)
	if err != nil || resp == nil {
		return nil, err
	}
	var absent []string
	for _, r := range postureRows(resp.Header) {
		if r.absent {
			absent = append(absent, r.header)
		}
	}
	return absent, nil
}
