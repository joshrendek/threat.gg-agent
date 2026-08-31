package modbus

import (
	"fmt"
	"strings"
	"testing"
)

// The avoid-list is the single highest-value test in this package. Conpot's
// template is in its public source tree, so it is catalogued by scanners.
// Shipping any of its values is self-identifying on the first probe, and
// the failure is silent -- the honeypot works perfectly and is simply
// known.
func TestPersonaMatchesNoPublishedHoneypotDefault(t *testing.T) {
	forbidden := map[string]string{
		// Conpot conpot/templates/default/modbus/modbus.xml
		"Siemens": "Conpot default Modbus VendorName",
		"SIMATIC": "Conpot default Modbus ProductCode",
		"S7-200":  "Conpot default Modbus MajorMinorRevision",
	}
	persona := map[string]string{
		"VendorName":         VendorName,
		"ProductCode":        ProductCode,
		"MajorMinorRevision": MajorMinorRevision,
		"VendorURL":          VendorURL,
		"ProductName":        ProductName,
		"ModelName":          ModelName,
	}
	for field, got := range persona {
		for bad, why := range forbidden {
			if got == bad {
				t.Errorf("%s = %q, which is a %s -- this value is published and self-identifying", field, got, why)
			}
		}
	}
}

// Conpot's default is detectable partly because the identity it reports
// (Siemens S7-200) contradicts the protocol it's actually speaking (Modbus
// is not an S7-200-native protocol). Internal coherence matters as much as
// any individual string.
func TestPersonaIsInternallyConsistent(t *testing.T) {
	if !strings.HasPrefix(ProductCode, "TM221") {
		t.Fatalf("ProductCode = %q; the checks below assume an M221-family SKU", ProductCode)
	}
	if !strings.Contains(ProductCode, "CE") {
		t.Errorf("ProductCode = %q must be the Ethernet-capable ('CE') M221 variant -- "+
			"a device answering Modbus/TCP must actually have the interface it's being reached through", ProductCode)
	}
	if ModelName != ProductCode {
		t.Errorf("ModelName %q != ProductCode %q; on a device with one catalog reference these should agree", ModelName, ProductCode)
	}
	if !strings.Contains(ProductName, "M221") {
		t.Errorf("ProductName = %q; must name the M221 line to agree with ProductCode %q", ProductName, ProductCode)
	}
}

// MajorMinorRevision follows the M221 documentation's own "V"+dotted-quad
// version format (e.g. "M221 Firmware V1.4", version string V1.4.0.3).
func TestMajorMinorRevisionFollowsSchneiderVersionFormat(t *testing.T) {
	var maj, min, patch, build int
	if _, err := fmt.Sscanf(MajorMinorRevision, "V%d.%d.%d.%d", &maj, &min, &patch, &build); err != nil {
		t.Fatalf("MajorMinorRevision %q is not the M221 dotted-quad form: %v", MajorMinorRevision, err)
	}
}

// UserApplicationName must stay empty until there is a way to attest what a
// specific real deployment's program is named -- see persona.go's comment.
func TestUserApplicationNameStaysEmptyUntilSourced(t *testing.T) {
	if UserApplicationName != "" {
		t.Errorf("UserApplicationName = %q, want empty until a real value can be sourced rather than invented", UserApplicationName)
	}
}
