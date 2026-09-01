package s7comm

import "encoding/binary"

// SZL-IDs this honeypot answers. Verified against
// s7comm_decode_ud_cpu_szl_subfunc / packet-s7comm_szl_ids.c.
const (
	szlModuleIdentification = 0x0011 // "Identification of the module" (also 0x0111)
	szlComponentIdent       = 0x001C // component/plant identification strings
)

// szlModuleIdentRecordLen is one SZL 0x0011 record's length in bytes:
// index(2) + MlfB(20, ASCII) + BGTyp(2) + Ausbg(2) + Ausbe(2) = 28.
// Verified against s7comm_decode_szl_id_0111_idx_0001.
const szlModuleIdentRecordLen = 28

// szlComponentRecordLen is one SZL 0x001C record's length in bytes. Every
// sub-index (name/tag/copyright/serial/etc.) is padded to the same 34 bytes
// -- index(2) + a 32-byte content region, verified field-by-field against
// s7comm_decode_szl_id_xy1c_idx_000x, where every case (24+8, 24+8, 32,
// 26+6, 24+8, 32, 32, 2+2+2+26, ...) sums to exactly 32.
const szlComponentRecordLen = 34

// szlRecord is one fixed-width SZL data-set record -- the unit
// s7comm_decode_ud_cpu_szl_subfunc loops list_count times over.
type szlRecord []byte

// szlLookup returns the records that answer an SZL-ID/Index request and
// whether this SZL is supported at all. Every returned record has length
// recordLen; the caller assembles the wire response
// (id, idx, list_len, list_count, records...).
//
// Only what the brief calls for is implemented: SZL 0x0011 indexes 0x0000
// (all implemented, see moduleIdentAllRecords) and 0x0001, and SZL 0x001C
// index 0x0000 (all implemented, see componentIdentAllRecords doc) plus
// 0x0001-0x0005/0x0007/0x0008. SZL 0x001C index
// 0x0009 is deliberately excluded -- see persona.go -- and everything else
// (0x001C index 0x0006/0x000a/0x000b, which a real SZL supports but this
// honeypot doesn't implement, any other SZL-ID entirely, or any index this
// switch doesn't name) falls through to "not supported", which the caller
// answers the same way a real CPU answers a list it doesn't have.
func szlLookup(id, idx uint16) (recordLen int, records []szlRecord, ok bool) {
	switch id {
	case szlModuleIdentification:
		switch idx {
		case 0x0000:
			return szlModuleIdentRecordLen, moduleIdentAllRecords(), true
		case 0x0001:
			return szlModuleIdentRecordLen, []szlRecord{buildModuleIdentRecord(idx)}, true
		}
	case szlComponentIdent:
		switch idx {
		case 0x0000:
			return szlComponentRecordLen, componentIdentAllRecords(), true
		case 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0007, 0x0008:
			return szlComponentRecordLen, []szlRecord{buildComponentRecord(idx)}, true
		}
	}
	return 0, nil, false
}

// buildModuleIdentRecord builds one SZL 0x0011 record. Layout verified
// against s7comm_decode_szl_id_0111_idx_0001: index(2), MlfB(20, ASCII),
// BGTyp(2), Ausbg(2), Ausbe(2).
func buildModuleIdentRecord(idx uint16) szlRecord {
	rec := make([]byte, szlModuleIdentRecordLen)
	binary.BigEndian.PutUint16(rec[0:2], idx)
	copy(rec[2:22], padASCII(OrderNumber, 20))
	binary.BigEndian.PutUint16(rec[22:24], ModuleTypeIDUnverified)
	binary.BigEndian.PutUint16(rec[24:26], ModuleReleaseFromUnverified)
	binary.BigEndian.PutUint16(rec[26:28], ModuleReleaseToUnverified)
	return rec
}

// moduleIdentAllRecords returns every SZL 0x0011 sub-index this honeypot
// implements, for a request with Index 0x0000. Only sub-indexes that are
// answered individually are included, so the wildcard never serves more than
// the per-index path does.
func moduleIdentAllRecords() []szlRecord {
	idxs := []uint16{0x0001}
	records := make([]szlRecord, len(idxs))
	for i, idx := range idxs {
		records[i] = buildModuleIdentRecord(idx)
	}
	return records
}

// buildComponentRecord builds one SZL 0x001C record for the given
// sub-index. Field widths verified against s7comm_decode_szl_id_xy1c_idx_000x;
// see szlComponentRecordLen for the per-index breakdown. Unimplemented
// indexes (which callers must not reach -- szlLookup gates this) fall back
// to an all-zero body, matching that function's own "default" case.
func buildComponentRecord(idx uint16) szlRecord {
	rec := make([]byte, szlComponentRecordLen)
	binary.BigEndian.PutUint16(rec[0:2], idx)
	body := rec[2:]

	switch idx {
	case 0x0001: // "Name of the PLC" (automation system name) -- 24 + 8 reserved
		copy(body, padASCII(SystemName, 24))
	case 0x0002: // "Name of the module" -- 24 + 8 reserved
		copy(body, padASCII(ModuleName, 24))
	case 0x0003: // Plant designation ("Tag") -- 32, no reserved tail
		copy(body, padASCII(PlantIdentification, 32))
	case 0x0004: // Copyright -- 26 + 6 reserved
		copy(body, padASCII(Copyright, 26))
	case 0x0005: // Serial number of the module -- 24 + 8 reserved
		copy(body, padASCII(SerialNumber, 24))
	case 0x0007: // CPU type name (module type name) -- 32, no reserved tail
		copy(body, padASCII(ModuleTypeName, 32))
	case 0x0008: // Memory card serial number -- 32, no reserved tail
		copy(body, padASCII(MemoryCardSerial, 32))
	}
	return rec
}

// componentIdentAllRecords returns every SZL 0x001C sub-index this honeypot
// implements, for a request with Index 0x0000.
//
// INVENTED (behaviour): the brief listed specific indexes to support but
// didn't say whether index 0x0000 should mean "give me everything" the way
// real S7 CPUs are documented to behave for multi-entry SZLs. Implemented
// here because it's cheap given the per-index records already exist, and
// because tools like nmap's s7-info/plcscan are known to query SZL 0x001C
// with index 0x0000 rather than walking each sub-index individually --
// answering only individual indexes would leave the single most common real
// probe unanswered. Index 0x0009 is excluded from this list for the same
// reason it isn't answered individually.
func componentIdentAllRecords() []szlRecord {
	idxs := []uint16{0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0007, 0x0008}
	records := make([]szlRecord, len(idxs))
	for i, idx := range idxs {
		records[i] = buildComponentRecord(idx)
	}
	return records
}

// padASCII returns s as exactly n bytes: space-padded on the right if
// shorter, truncated if longer. Wireshark's dissector decodes these fields
// as plain ENC_ASCII of a fixed width, which confirms the WIDTH but not the
// padding byte a real device uses to fill it. INVENTED: space padding was
// chosen over NUL padding because it renders as plausible fixed-width text
// in a hex/string view rather than a run of embedded nulls, which is a
// weaker (but not verified) assumption -- flagged per the brief's
// instruction to call out anything neither it nor the dissector settled.
func padASCII(s string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	copy(b, s)
	return b
}
