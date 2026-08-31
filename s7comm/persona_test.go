package s7comm

import (
	"fmt"
	"strings"
	"testing"
)

// The avoid-list is the single highest-value test in this package. Every value
// here is published: Conpot's template is in its public source tree and nmap's
// example is in its own documentation, so both are catalogued by scanners.
// Shipping any of them is self-identifying on the first probe, and the failure
// is silent -- the honeypot works perfectly and is simply known.
func TestPersonaMatchesNoPublishedHoneypotDefault(t *testing.T) {
	forbidden := map[string]string{
		// Conpot conpot/templates/default/template.xml
		"CP 443-1 EX40":            "Conpot default system name",
		"Mouser Factory":           "Conpot default plant identification",
		"IM151-8 PN/DP CPU":        "Conpot default module type",
		"88111222":                 "Conpot default serial number",
		"Technodrome":              "Conpot default databus system name",
		"Siemens, SIMATIC, S7-200": "Conpot default system description",
		// nmap s7-info.nse documented example output
		"6ES7 315-2AG10-0AB0": "nmap documentation example order number",
		"S C-X4U421302009":    "nmap documentation example serial",
		"SIMATIC 300(1)":      "nmap documentation example system name",
		"CPU 315-2 DP":        "nmap documentation example module type",
	}
	persona := map[string]string{
		"OrderNumber":         OrderNumber,
		"BasicHardware":       BasicHardware,
		"ModuleTypeName":      ModuleTypeName,
		"SystemName":          SystemName,
		"SerialNumber":        SerialNumber,
		"FirmwareVersion":     FirmwareVersion,
		"PlantIdentification": PlantIdentification,
		"MemoryCardSerial":    MemoryCardSerial,
		"ModuleName":          ModuleName,
	}
	for field, got := range persona {
		for bad, why := range forbidden {
			if got == bad {
				t.Errorf("%s = %q, which is a %s -- this value is published and self-identifying", field, got, why)
			}
		}
	}
}

// "Original Siemens Equipment" appears in Conpot's template but is the genuine
// string real devices return. Avoiding it because it looks like a Conpot value
// would itself be a tell, so pin that we keep it.
func TestCopyrightKeepsTheGenuineSiemensString(t *testing.T) {
	if Copyright != "Original Siemens Equipment" {
		t.Errorf("Copyright = %q, want the genuine Siemens string; it appears in Conpot's template "+
			"but real devices return it, so changing it to avoid Conpot would be the tell", Copyright)
	}
}

// Conpot's default is detectable partly because it pairs parts that never ship
// together (a CP 443-1 system name with an IM151-8 module type). Internal
// coherence matters as much as any individual value.
func TestPersonaIsInternallyConsistent(t *testing.T) {
	if !strings.Contains(OrderNumber, "315-2EH") {
		t.Fatalf("OrderNumber = %q; the checks below assume the 315-2EH (PN/DP) variant", OrderNumber)
	}
	// -2EH is the PN/DP variant. Claiming "DP" alone would contradict the order number.
	if !strings.Contains(ModuleTypeName, "PN/DP") {
		t.Errorf("ModuleTypeName = %q contradicts OrderNumber %q: -2EH14 is the PN/DP CPU, not DP-only",
			ModuleTypeName, OrderNumber)
	}
	if BasicHardware != OrderNumber {
		t.Errorf("BasicHardware %q != OrderNumber %q; on an integrated CPU real devices report the same MlfB",
			BasicHardware, OrderNumber)
	}
	if !strings.HasPrefix(OrderNumber, "6ES7 ") {
		t.Errorf("OrderNumber = %q; S7-300/400 order numbers begin 6ES7", OrderNumber)
	}
}

// S7-300 firmware tops out at V3.3.17. Claiming higher describes a device that
// cannot exist -- the same class of error as advertising a product version whose
// capabilities contradict its own endpoints.
func TestFirmwareVersionIsPossibleForAnS7300(t *testing.T) {
	var maj, min, patch int
	if _, err := fmt.Sscanf(FirmwareVersion, "%d.%d.%d", &maj, &min, &patch); err != nil {
		t.Fatalf("FirmwareVersion %q is not dotted-triple form: %v", FirmwareVersion, err)
	}
	if maj > 3 || (maj == 3 && min > 3) || (maj == 3 && min == 3 && patch > 17) {
		t.Errorf("FirmwareVersion = %q exceeds the S7-300 maximum of 3.3.17", FirmwareVersion)
	}
}

// Serial format is sourced even though the value is invented: "S C-" plus plant
// code and a date encoding. A serial that does not even look right is a cheaper
// tell than one whose encoded date is subtly implausible.
func TestSerialNumberFollowsTheSiemensShape(t *testing.T) {
	if !strings.HasPrefix(SerialNumber, "S C-") {
		t.Errorf("SerialNumber = %q; real S7-300 serials begin \"S C-\"", SerialNumber)
	}
	if len(SerialNumber) < 10 {
		t.Errorf("SerialNumber = %q is implausibly short", SerialNumber)
	}
	if !strings.Contains(SerialNumberProvenance, "INVENTED") {
		t.Error("SerialNumberProvenance must keep saying INVENTED until the date encoding is verified")
	}
}
