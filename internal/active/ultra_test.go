package active

import (
	"testing"
)

// Phase 3: the ultra gate defaults off and toggles explicitly —
// advanced behavior must never depend on ultra existing.
func TestUltraGateDefaultOff(t *testing.T) {
	SetUltraConfirm(false)
	if UltraConfirmEnabled() {
		t.Fatal("ultra gate must default off")
	}
	SetUltraConfirm(true)
	if !UltraConfirmEnabled() {
		t.Fatal("ultra gate must toggle on")
	}
	SetUltraConfirm(false)
}
