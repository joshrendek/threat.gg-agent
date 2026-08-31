// Package modbus emulates a Schneider Electric Modicon M221 logic
// controller (a TM221CE40T) speaking Modbus/TCP on port 502.
//
// It is a honeypot: nothing it reports is real, and nothing an attacker
// asks it to do is ever executed.
package modbus

// The device persona: every identity value this honeypot reports about
// itself via Read Device Identification (function 0x2B / MEI 0x0E -- see
// deviceid.go).
//
// WHY THIS FILE EXISTS SEPARATELY: same discipline s7comm/persona.go
// established (PRD 033) -- we cannot buy a real M221 to diff against, so
// the next best thing is to make every invented value visible in one
// place, individually labelled with its provenance, rather than scattered
// through the protocol code where "where did this number come from?" is
// unanswerable.
//
// Provenance labels used below (identical meaning to s7comm/persona.go):
//
//	SOURCED   attested by public documentation, a vendor's own real device
//	          identification strings, or public vulnerability/scan data
//	DERIVED   follows a documented rule or uses a real value, but this
//	          exact combination or field-mapping is our choice
//	INVENTED  no source; a plausible guess and a known-unknown
//
// ─── THE AVOID-LIST ────────────────────────────────────────────────────────
//
// Conpot is the canonical open-source ICS honeypot; its default template
// (conpot/templates/default/modbus/modbus.xml) configures its Modbus
// personality to answer as a Siemens S7-200, and is catalogued by scanners
// as a result. Never ship:
//
//	"Siemens" (VendorName), "SIMATIC" (ProductCode), "S7-200" (MajorMinorRevision)
//
// It is also internally incoherent in exactly the way s7comm's own
// avoid-list documents for the S7comm side of this same default: a Siemens
// S7-200 does not speak Modbus/TCP natively at all (S7-200s are S7comm/PPI
// devices; the "S7-200 modbus" combination is Conpot's own construction,
// not a real Siemens product line), so a device claiming to BE one while
// answering Modbus/TCP is a mismatch a careful attacker notices independent
// of whether any single string is recognised.
const (
	// SOURCED. Schneider Electric's real, exact vendor string -- and
	// genuinely what Schneider hardware returns for VendorName in Read
	// Device Identification (e.g. the ATV320 drive line reports "Schneider
	// Electric" here).
	VendorName = "Schneider Electric"

	// SOURCED (the model itself, a real currently-catalogued part) /
	// DERIVED (using it as the ProductCode value). TM221CE40T is a genuine
	// Modicon M221 CPU: 40 I/O, Ethernet + Modbus/TCP.
	//
	// Chosen deliberately as the Ethernet ("...CE...") variant, not a
	// serial-only M221 SKU: an internet-reachable device must actually have
	// the interface it's being reached through, or the persona contradicts
	// its own connectivity -- the same reasoning s7comm's persona.go used
	// to pick the PN/DP CPU over the DP-only variant.
	ProductCode = "TM221CE40T"

	// SOURCED. A real firmware version that shipped for the M221 line --
	// confirmed via NVD's CPE dictionary
	// (cpe:2.3:o:se:modicon_m221_firmware:1.6.2.0) and CISA advisories
	// ICSA-18-240-01/ICSA-18-240-02, which describe this exact version as
	// the fix for several M221 vulnerabilities. Using a genuinely-shipped,
	// already-patched version is deliberate: it is real, and reporting it
	// does not itself claim the device is vulnerable.
	//
	// Format: M221 documentation (e.g. "M221 Firmware V1.4", released
	// 2016-01-25) uses this exact "V" + dotted-quad style.
	MajorMinorRevision = "V1.6.2.0"

	// SOURCED. Schneider Electric's real corporate domain.
	VendorURL = "www.schneider-electric.com"

	// SOURCED. "Modicon M221" is the real product line/series name this CPU
	// belongs to -- distinct from ProductCode, which is the specific
	// catalog reference within that line.
	ProductName = "Modicon M221"

	// DERIVED. On a device with a single catalog reference, ModelName and
	// ProductCode coinciding is the internally consistent choice -- the
	// same reasoning s7comm/persona.go uses for BasicHardware == OrderNumber
	// (real devices report the same MlfB for the module and its basic
	// hardware on an integrated CPU).
	ModelName = ProductCode

	// INVENTED, and deliberately empty. UserApplicationName holds the
	// operator's IEC 61131 program name; there is no way to attest what a
	// specific real deployment's program is named. Empty is the same
	// higher-fidelity choice s7comm/persona.go makes for
	// PlantIdentification: an optional, operator-set field left blank is
	// ordinary and unremarkable, whereas a fabricated program name is both
	// a tell (checkable against nothing) and a needless invention.
	UserApplicationName = ""
)
