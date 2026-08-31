// Package s7comm emulates a Siemens S7-300 class PLC speaking classic S7comm
// over TCP/102 (TPKT + ISO-COTP + S7 PDUs).
//
// It is a honeypot: nothing it reports is real, and nothing an attacker asks it
// to do is ever executed.
package s7comm

// The device persona: every identity value this honeypot reports about itself.
//
// WHY THIS FILE EXISTS SEPARATELY (threat_gg-4zzd.3): PRD 033 established that
// everything with ground truth was correct and both shipped bugs were in the
// invented parts. We cannot buy an S7-300 to diff against, so the next best
// thing is to make every invented value visible in one place, individually
// labelled with its provenance, rather than scattered through the protocol code
// where "where did this number come from?" is unanswerable.
//
// Provenance labels used below:
//
//	SOURCED   attested by public documentation or real-device scan output
//	DERIVED   follows a documented rule, but this exact value is our choice
//	INVENTED  no source; a plausible guess and a known-unknown
//
// ─── THE AVOID-LIST ────────────────────────────────────────────────────────
//
// Two sets of values are self-identifying and must never appear here.
//
//  1. Conpot's defaults. Conpot is the canonical open-source ICS honeypot; its
//     template is public and therefore catalogued by scanners. Never ship:
//     "CP 443-1 EX40", "Mouser Factory", "IM151-8 PN/DP CPU", "88111222",
//     "Technodrome", "Siemens, SIMATIC, S7-200".
//     Conpot's default is also internally incoherent -- a CP 443-1 (an S7-400
//     comms processor) paired with an IM151-8 (ET200S distributed I/O). Parts
//     that never ship together are a tell on their own, independent of whether
//     any single string is recognised.
//
//  2. Nmap's own documentation example. It is quoted in every write-up about
//     s7-info and is copied at least as widely as Conpot's defaults. Never
//     ship: "6ES7 315-2AG10-0AB0", "S C-X4U421302009", "SIMATIC 300(1)",
//     module type "CPU 315-2 DP".
//
// COUNTER-TRAP: "Original Siemens Equipment" LOOKS like a Conpot value but is
// the genuine copyright string real Siemens devices return. Keep it. Avoiding
// it because it appears in Conpot's template would itself be the tell.
const (
	// SOURCED (format) / DERIVED (this value). Order number, "MlfB" in the S7
	// protocol. 6ES7 = the Step 7 S7-300/400 family; 315-2EH14 is the 315-2
	// PN/DP CPU with 384 KB work memory and an integrated PROFINET interface.
	//
	// Chosen over the 315-2 DP (6ES7 315-2AG10) deliberately: the DP variant has
	// no onboard Ethernet, so an internet-reachable one implies a separate CP
	// module we would then also have to be consistent about. A PN/DP CPU
	// explains its own connectivity. It is also NOT nmap's documented example.
	OrderNumber = "6ES7 315-2EH14-0AB0"

	// DERIVED. Real devices report the same MlfB for the module and its basic
	// hardware on an integrated CPU; they diverge only where hardware is a
	// separate part. Keeping them equal is the consistent choice here.
	BasicHardware = OrderNumber

	// SOURCED (naming convention) / DERIVED (this value). Must agree with the
	// order number above: -2EH14 IS the PN/DP variant, so this cannot read
	// "CPU 315-2 DP" without contradicting OrderNumber. That contradiction is
	// exactly the class of error that makes Conpot's default detectable.
	ModuleTypeName = "CPU 315-2 PN/DP"

	// INVENTED. The automation system name is operator-chosen on real devices,
	// so any plausible string is defensible -- but the DEFAULT is "SIMATIC
	// 300(1)", which is both nmap's example and what an unconfigured device
	// reports. A device that is configured enough to be on the internet but
	// still carries the factory default name is a slightly odd combination, so
	// this is a plausible operator-set value instead.
	SystemName = "S7300/ET200M station"

	// SOURCED. The genuine copyright string Siemens devices return. See the
	// counter-trap note above -- this one is supposed to match.
	Copyright = "Original Siemens Equipment"

	// INVENTED, and the weakest value here -- see SerialNumberProvenance.
	SerialNumber = "S C-C2UY19924"

	// SOURCED (ceiling) / DERIVED (this value). S7-300 firmware tops out at
	// V3.3.17, so anything above that is an impossible device -- the same class
	// of mistake as claiming an Ollama version whose features contradict its
	// endpoints. V3.2.7 is comfortably inside the real range for this CPU.
	FirmwareVersion = "3.2.7"

	// SOURCED (behaviour). Plant designation is frequently EMPTY on real
	// internet-exposed devices because it is an optional commissioning field
	// most integrators never fill in. Empty is therefore the higher-fidelity
	// choice, and it also avoids inventing a fake company name -- which is both
	// a tell and needlessly impersonates a real business if the name collides.
	PlantIdentification = ""
)

// SerialNumberProvenance documents the one field we are least sure of, so that
// a future reader does not mistake it for attested data.
//
// The format is sourced: Siemens S7-300 serials are "S C-" followed by a plant
// code, then a character encoding the production year and one encoding the
// month, then a sequence. "S" = 2004 in the year encoding, so nmap's documented
// "S C-X4U421302009" decodes to 2009, month 4.
//
// What is NOT verified: whether the year letters continue alphabetically past
// "Z" (2011) or wrap, and the exact month letters used for October-December.
// This value therefore uses a year character inside the range we can justify,
// but the encoded date has NOT been confirmed to be internally consistent with
// a plausible manufacturing date for a -2EH14 CPU.
//
// RISK: an attacker who decodes serials could find the date implausible for
// this order number. That is a deep check and unlikely, but it is a real
// known-unknown rather than an attested value.
//
// TO CLOSE THIS: decode several real S7-300 serials from public scan data and
// confirm the year/month mapping, then either confirm or replace this value.
const SerialNumberProvenance = "INVENTED: format sourced, encoded production date unverified"

// MemoryCardSerial is returned for SZL 0x001C index 0x0008.
//
// INVENTED. Deliberately unrelated in shape to SerialNumber: on a real device
// the MMC is a separate part from the CPU, with its own numbering, so making
// this look like a sibling of the CPU serial would be wrong.
const MemoryCardSerial = "MMC 3E4F1A97"

// For SZL 0x001C index 0x0009 (manufacturer and profile of a CPU module).
//
// INVENTED — DO NOT SERVE THESE UNTIL VERIFIED.
//
// These were initially written down as if sourced. They are not: no source was
// consulted for Siemens' manufacturer ID or the SIMATIC CPU profile ID, and
// plausible-looking constants are precisely the failure mode this file exists to
// prevent. Recording the mistake rather than quietly deleting it, because the
// same reflex will recur on the next structured SZL field.
//
// TO CLOSE THIS: read the real values out of Wireshark's
// packet-s7comm_szl_ids.c (it decodes these fields and carries the known IDs) or
// a real capture, then relabel as SOURCED.
//
// UNTIL THEN: index 0x0009 should not be answered at all. Returning a plausible
// wrong manufacturer ID is worse than returning the "SZL not available" error a
// real device gives for an index it does not support — one is a contradiction a
// scanner can check against a known registry, the other is ordinary behaviour.
const (
	ManufacturerIDUnverified      = 0x002A
	ProfileIDUnverified           = 0xF600
	ProfileSpecificTypeUnverified = 0x0001
)

// ─── VALUES ADDED WHILE IMPLEMENTING THE PROTOCOL (threat_gg-4zzd) ─────────
//
// The fields below were not anticipated when this file was written; they
// surfaced only once the exact SZL wire layouts were pulled from Wireshark's
// packet-s7comm_szl_ids.c. Following this file's own rule: invented values
// get a label and a comment here, not a bare magic number in szl.go.

// ModuleName is returned for SZL 0x001C index 0x0002 ("Name of the module"),
// which Wireshark's dissector documents as distinct from ModuleTypeName
// (index 0x0007, the CPU's hardware type name).
//
// SOURCED (behaviour) / DERIVED (this value). Left empty for the same reason
// as PlantIdentification above: it is an operator-set commissioning field,
// so empty is the higher-fidelity choice for an otherwise-unconfigured
// device, and it avoids inventing a second fake facility string alongside
// PlantIdentification that would have to stay consistent with it.
const ModuleName = ""

// MaxAMQCalling/MaxAMQCalled are negotiated in Setup Communication (S7
// header function 0xF0) -- the number of outstanding, unacknowledged jobs
// each side may have in flight.
//
// DERIVED. The S7-300 family is documented to support exactly one
// outstanding job in each direction (the S7-400 family supports several),
// so both are 1 -- chosen because it matches the CPU family in OrderNumber,
// not because 1 is a common default to copy.
const (
	MaxAMQCalling = 1
	MaxAMQCalled  = 1

	// NegotiatedPDULength is the S7 (not COTP/TPDU) PDU size this device
	// offers in Setup Communication.
	//
	// DERIVED. 240 bytes is the widely-documented default for the S7-300
	// family; the 400 family and TIA-generation CPUs commonly negotiate 480
	// or more. 240 was chosen to match the CPU family already fixed by
	// OrderNumber, not copied from any single tool's default.
	NegotiatedPDULength = 240
)

// SZL 0x0011 index 0x0001 ("module identification") carries the MlfB order
// number (OrderNumber, above) plus three numeric fields Wireshark's
// dissector decodes but does not name authoritatively: BGTyp (an internal
// Siemens hardware-classification code) and two release counters, Ausbg and
// Ausbe.
//
// INVENTED, and flagged rather than guessed at -- exactly the SZL 0x001C
// index 0x0009 situation above. No source was consulted for what a real
// 6ES7 315-2EH14 reports in these three fields, and a plausible-looking
// non-zero code is a worse tell than an honest zero, so all three are zero
// until a real capture confirms otherwise. Unlike index 0x0009, this index
// cannot simply be withheld -- the brief requires answering 0x0011/0x0001 at
// all, and these three fields are part of that one fixed-width record.
//
// TO CLOSE THIS: decode a real SZL 0x0011/0x0001 response from a 315-2
// PN/DP and replace these with sourced values.
const (
	ModuleTypeIDUnverified      = 0x0000
	ModuleReleaseFromUnverified = 0x0000
	ModuleReleaseToUnverified   = 0x0000
)
