package modbus

import "fmt"

// Read Device Identification (function 0x2B, MEI type 0x0E) is Modbus's
// fingerprinting equivalent of S7comm's SZL read: it is what a scanner
// reads to identify vendor/product/revision, so getting the byte layout
// exactly right matters as much as the persona values it carries (see
// persona.go).
//
// Request layout, verified against Wireshark's packet-mbtcp.c
// dissect_modbus_request ENCAP_INTERFACE_TRANSP/READ_DEVICE_ID case: MEI
// type(1), Read Device ID code(1), Object Id(1).
//
// Response layout, verified against dissect_modbus_response's
// READ_DEVICE_ID case: MEI type(1), Read Device ID code(1) [echoed],
// Conformity level(1), More Follows(1), Next Object Id(1), Number of
// Objects(1), then that many [Object Id(1), Object Length(1), Object Value
// (Object Length bytes)] triplets.
const (
	meiTypeReadDeviceID = 0x0E

	// Read Device ID code values, verified against packet-mbtcp.c's
	// read_device_id_vals table.
	readDeviceIDBasic    = 0x01 // Object IDs 0x00-0x02 only
	readDeviceIDRegular  = 0x02 // Basic + optional Object IDs 0x03-0x06
	readDeviceIDExtended = 0x03 // + vendor-specific Object IDs 0x80-0xFF
	readDeviceIDSpecific = 0x04 // exactly the one Object Id named in the request

	// conformityRegularIndividual is this device's advertised conformity
	// level, verified against packet-mbtcp.c's conformity_level_vals table:
	// 0x82 = "Regular Device Identification (stream and individual)". This
	// device implements Basic + Regular (Object Ids 0x00-0x06) via both
	// stream (Basic/Regular request codes) and individual (Specific
	// request code) access, but no Extended/vendor-specific objects -- see
	// handleReadDeviceID's readDeviceIDExtended case.
	conformityRegularIndividual = 0x82

	// Object Id values for the Basic/Regular tables, verified against
	// packet-mbtcp.c's object_id_vals table.
	objVendorName          = 0x00
	objProductCode         = 0x01
	objMajorMinorRevision  = 0x02
	objVendorURL           = 0x03
	objProductName         = 0x04
	objModelName           = 0x05
	objUserApplicationName = 0x06
)

// deviceIDObject is one Object Id/value pair this honeypot can answer.
type deviceIDObject struct {
	id    byte
	value string
}

// deviceIDObjects is every object this honeypot knows, in ascending
// Object Id order -- the first 3 are the Basic set, all 7 are the Regular
// set. See persona.go for the values and their provenance.
var deviceIDObjects = []deviceIDObject{
	{objVendorName, VendorName},
	{objProductCode, ProductCode},
	{objMajorMinorRevision, MajorMinorRevision},
	{objVendorURL, VendorURL},
	{objProductName, ProductName},
	{objModelName, ModelName},
	{objUserApplicationName, UserApplicationName},
}

// handleReadDeviceID answers function 0x2B. pdu[0] is the function code
// itself (0x2B); pdu[1:] is the MEI-type-tagged body.
func handleReadDeviceID(pdu []byte, sess *session) []byte {
	const fc = fnReadDeviceID

	if len(pdu) != 4 {
		sess.record(operation{Kind: "malformed_read_device_id", Detail: fmt.Sprintf("pdu %d bytes, want 4", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	meiType := pdu[1]
	readCode := pdu[2]
	objectID := pdu[3]

	if meiType != meiTypeReadDeviceID {
		// The only other real MEI type (0x0D, CANopen General Reference) has
		// no fidelity value for an internet-exposed device and is declined
		// rather than acknowledged -- see pdu.go's package doc on never
		// acking an unsupported function as success.
		sess.record(operation{Kind: fmt.Sprintf("unsupported_mei=0x%02X", meiType), Detail: "MEI type is not Read Device Identification", Raw: pdu, Handled: false})
		return buildException(fc, excIllegalFunction)
	}

	switch readCode {
	case readDeviceIDBasic:
		return respondDeviceID(fc, readCode, sess, "read_device_id_basic", deviceIDObjects[:3])
	case readDeviceIDRegular:
		return respondDeviceID(fc, readCode, sess, "read_device_id_regular", deviceIDObjects)
	case readDeviceIDSpecific:
		for _, obj := range deviceIDObjects {
			if obj.id == objectID {
				return respondDeviceID(fc, readCode, sess, "read_device_id_specific", []deviceIDObject{obj})
			}
		}
		sess.record(operation{Kind: "read_device_id_specific", Detail: fmt.Sprintf("object_id=0x%02X not implemented", objectID), Handled: false})
		return buildException(fc, excIllegalDataAddress)
	case readDeviceIDExtended:
		// No vendor-specific (0x80-0xFF) objects are defined for this
		// device -- see persona.go. Rather than invent one (checkable
		// against nothing, and a worse tell than declining), this device
		// declines Extended entirely: its advertised conformity level is
		// Regular, not Extended, so a real client asking a
		// Regular-conformant device for Extended gets an error, not a
		// fabricated empty-but-successful reply.
		sess.record(operation{Kind: "read_device_id_extended", Detail: "extended identification not supported by this device", Handled: false})
		return buildException(fc, excIllegalDataValue)
	default:
		sess.record(operation{Kind: fmt.Sprintf("unsupported_read_device_id_code=0x%02X", readCode), Detail: "read device id code not implemented", Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
}

// respondDeviceID builds a Read Device Identification success response
// carrying objects.
//
// More Follows and Next Object Id are always 0x00 here -- DESIGN CHOICE,
// not a sourced fact about a specific read-device-id code's semantics:
// every object this honeypot has fits in a single response (a handful of
// short strings, well under the 253-byte PDU limit), so a real client
// asking for more never needs a follow-up request.
func respondDeviceID(fc, readCode byte, sess *session, kind string, objects []deviceIDObject) []byte {
	body := make([]byte, 0, 6+64)
	body = append(body,
		meiTypeReadDeviceID,
		readCode,
		conformityRegularIndividual,
		0x00, // more follows
		0x00, // next object id
		byte(len(objects)),
	)
	for _, obj := range objects {
		body = append(body, obj.id, byte(len(obj.value)))
		body = append(body, []byte(obj.value)...)
	}

	sess.advance(stageIdentity)
	sess.record(operation{Kind: kind, Detail: fmt.Sprintf("objects=%d", len(objects)), Handled: true})

	resp := make([]byte, 1+len(body))
	resp[0] = fc
	copy(resp[1:], body)
	return resp
}
