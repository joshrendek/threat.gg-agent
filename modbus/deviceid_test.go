package modbus

import "testing"

// TestReadDeviceIDBasicReturnsThreeMandatoryObjects confirms the Basic
// (code 1) request returns exactly VendorName/ProductCode/
// MajorMinorRevision, in that object-id order, with the persona's values.
func TestReadDeviceIDBasicReturnsThreeMandatoryObjects(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDBasic, 0x00}
	resp := handlePDU(req, "192.0.2.30", sess)

	objs := parseDeviceIDObjects(t, resp)
	if len(objs) != 3 {
		t.Fatalf("Basic response returned %d objects, want 3", len(objs))
	}
	want := map[byte]string{
		objVendorName:         VendorName,
		objProductCode:        ProductCode,
		objMajorMinorRevision: MajorMinorRevision,
	}
	for _, o := range objs {
		if o.value != want[o.id] {
			t.Errorf("object 0x%02X = %q, want %q", o.id, o.value, want[o.id])
		}
	}
}

// TestReadDeviceIDRegularReturnsAllSevenObjects confirms the Regular (code
// 2) request returns the Basic set plus VendorURL/ProductName/ModelName/
// UserApplicationName.
func TestReadDeviceIDRegularReturnsAllSevenObjects(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDRegular, 0x00}
	resp := handlePDU(req, "192.0.2.31", sess)

	objs := parseDeviceIDObjects(t, resp)
	if len(objs) != 7 {
		t.Fatalf("Regular response returned %d objects, want 7", len(objs))
	}
}

// TestReadDeviceIDSpecificReturnsOnlyTheRequestedObject covers code 4
// (individual access): only the one named object id comes back.
func TestReadDeviceIDSpecificReturnsOnlyTheRequestedObject(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDSpecific, objProductName}
	resp := handlePDU(req, "192.0.2.32", sess)

	objs := parseDeviceIDObjects(t, resp)
	if len(objs) != 1 || objs[0].id != objProductName || objs[0].value != ProductName {
		t.Fatalf("specific response = %+v, want exactly [{0x%02X %q}]", objs, objProductName, ProductName)
	}
}

// TestReadDeviceIDSpecificUnknownObjectIsIllegalDataAddress confirms
// requesting an object id this honeypot doesn't have is rejected, not
// answered with a fabricated value.
func TestReadDeviceIDSpecificUnknownObjectIsIllegalDataAddress(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDSpecific, 0x50} // vendor-specific range, undefined here
	resp := handlePDU(req, "192.0.2.33", sess)

	if resp[0] != fnReadDeviceID|0x80 || resp[1] != excIllegalDataAddress {
		t.Errorf("response = % x, want exception illegal_data_address", resp)
	}
}

// TestReadDeviceIDExtendedIsDeclined confirms Extended (code 3) -- which
// this device does not implement (no vendor-specific objects are defined)
// -- is rejected with an exception rather than answered with an empty but
// nominally successful reply.
func TestReadDeviceIDExtendedIsDeclined(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDExtended, 0x00}
	resp := handlePDU(req, "192.0.2.34", sess)

	if resp[0] != fnReadDeviceID|0x80 || resp[1] != excIllegalDataValue {
		t.Errorf("response = % x, want exception illegal_data_value", resp)
	}
}

// TestReadDeviceIDUnsupportedMEITypeIsDeclined confirms a MEI type other
// than Read Device Identification (0x0E) is rejected.
func TestReadDeviceIDUnsupportedMEITypeIsDeclined(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, 0x0D, 0x01, 0x00} // 0x0D = CANopen General Reference, not implemented
	resp := handlePDU(req, "192.0.2.35", sess)

	if resp[0] != fnReadDeviceID|0x80 || resp[1] != excIllegalFunction {
		t.Errorf("response = % x, want exception illegal_function", resp)
	}
}

// TestReadDeviceIDUnsupportedReadCodeIsDeclined confirms an invalid read
// device id code (outside 1-4) is rejected rather than guessed at.
func TestReadDeviceIDUnsupportedReadCodeIsDeclined(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, 0x09, 0x00}
	resp := handlePDU(req, "192.0.2.36", sess)

	if resp[0] != fnReadDeviceID|0x80 || resp[1] != excIllegalDataValue {
		t.Errorf("response = % x, want exception illegal_data_value", resp)
	}
}

// TestReadDeviceIDConformityLevelAndFramingFields confirms the response
// header fields (MEI type, echoed read-device-id code, conformity level,
// more-follows, next-object-id) match this device's advertised support --
// verified byte-for-byte against Wireshark's packet-mbtcp.c dissector
// layout.
func TestReadDeviceIDConformityLevelAndFramingFields(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDBasic, 0x00}
	resp := handlePDU(req, "192.0.2.37", sess)

	if resp[0] != fnReadDeviceID {
		t.Errorf("function = 0x%02X, want 0x2B", resp[0])
	}
	if resp[1] != meiTypeReadDeviceID {
		t.Errorf("MEI type = 0x%02X, want 0x0E", resp[1])
	}
	if resp[2] != readDeviceIDBasic {
		t.Errorf("echoed read device id code = 0x%02X, want 0x01", resp[2])
	}
	if resp[3] != conformityRegularIndividual {
		t.Errorf("conformity level = 0x%02X, want 0x%02X", resp[3], conformityRegularIndividual)
	}
	if resp[4] != 0x00 {
		t.Errorf("more follows = 0x%02X, want 0x00 (everything fits in one response)", resp[4])
	}
	if resp[5] != 0x00 {
		t.Errorf("next object id = 0x%02X, want 0x00", resp[5])
	}
}

type parsedObj struct {
	id    byte
	value string
}

// parseDeviceIDObjects decodes the object list out of a Read Device
// Identification success response: resp[6] is numObjects, then repeated
// [id(1) length(1) value(length)] starting at offset 7.
func parseDeviceIDObjects(t *testing.T, resp []byte) []parsedObj {
	t.Helper()
	if len(resp) < 7 {
		t.Fatalf("response %x too short to be a Read Device Identification success reply", resp)
	}
	numObjects := int(resp[6])
	var objs []parsedObj
	offset := 7
	for i := 0; i < numObjects; i++ {
		if offset+2 > len(resp) {
			t.Fatalf("response truncated while parsing object %d: %x", i, resp)
		}
		id := resp[offset]
		length := int(resp[offset+1])
		offset += 2
		if offset+length > len(resp) {
			t.Fatalf("response truncated while parsing object %d's value: %x", i, resp)
		}
		objs = append(objs, parsedObj{id: id, value: string(resp[offset : offset+length])})
		offset += length
	}
	return objs
}
