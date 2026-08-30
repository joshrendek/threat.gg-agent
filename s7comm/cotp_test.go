package s7comm

import "testing"

// buildTestCR builds a minimal, well-formed COTP CR TPDU (LI, type, dst-ref,
// src-ref, class, then src-tsap/dst-tsap/tpdu-size variable-part entries) --
// the shape a real S7 client sends.
func buildTestCR(srcRef uint16, srcTSAP, dstTSAP []byte, tpduSizeByte byte) []byte {
	vp := []byte{}
	vp = append(vp, vpTPDUSize, 1, tpduSizeByte)
	vp = append(vp, vpSrcTSAP, byte(len(srcTSAP)))
	vp = append(vp, srcTSAP...)
	vp = append(vp, vpDstTSAP, byte(len(dstTSAP)))
	vp = append(vp, dstTSAP...)

	li := 6 + len(vp)
	b := make([]byte, 1+li)
	b[0] = byte(li)
	b[1] = cotpCR
	b[2], b[3] = 0x00, 0x00 // dst-ref, always 0 on a fresh CR
	b[4] = byte(srcRef >> 8)
	b[5] = byte(srcRef)
	b[6] = 0x00 // class 0
	copy(b[7:], vp)
	return b
}

func TestParseCRThenBuildCCEchoesTSAPsAndRefs(t *testing.T) {
	srcTSAP := []byte{0x01, 0x00}
	dstTSAP := []byte{0x03, 0x02}
	cr := buildTestCR(0x1234, srcTSAP, dstTSAP, 0x0A)

	parsed, err := parseCR(cr)
	if err != nil {
		t.Fatalf("parseCR: %v", err)
	}
	if parsed.srcRef != 0x1234 {
		t.Errorf("srcRef = 0x%04x, want 0x1234", parsed.srcRef)
	}
	if parsed.tpduSizeByte != 0x0A {
		t.Errorf("tpduSizeByte = 0x%02x, want 0x0a", parsed.tpduSizeByte)
	}

	cc := buildCC(parsed, 0x5678)
	if cc[1] != cotpCC {
		t.Fatalf("CC type byte = 0x%02x, want 0x%02x", cc[1], cotpCC)
	}
	dstRef := uint16(cc[2])<<8 | uint16(cc[3])
	if dstRef != 0x1234 {
		t.Errorf("CC dst-ref = 0x%04x, want the CR's src-ref 0x1234", dstRef)
	}
	ccSrcRef := uint16(cc[4])<<8 | uint16(cc[5])
	if ccSrcRef != 0x5678 {
		t.Errorf("CC src-ref = 0x%04x, want our chosen 0x5678", ccSrcRef)
	}

	// Re-parse the CC's variable part as if it were a CR (same TLV shape)
	// to check the TSAPs were swapped, not just copied.
	var reparsed cotpConnectRequest
	parseCOTPVariablePart(cc[7:], &reparsed)
	if string(reparsed.srcTSAP) != string(dstTSAP) {
		t.Errorf("CC src-tsap = % x, want the CR's dst-tsap % x", reparsed.srcTSAP, dstTSAP)
	}
	if string(reparsed.dstTSAP) != string(srcTSAP) {
		t.Errorf("CC dst-tsap = % x, want the CR's src-tsap % x", reparsed.dstTSAP, srcTSAP)
	}
}

func TestParseCRAcceptsArbitraryTSAPs(t *testing.T) {
	// Real captures show scanners enumerating rack/slot by trying many
	// different destination TSAPs. parseCR must not reject any of them.
	for _, dstTSAP := range [][]byte{{0x03, 0x00}, {0x03, 0x01}, {0x03, 0x02}, {0x02, 0x00}, {0x03, 0xFF}} {
		cr := buildTestCR(0x0001, []byte{0x01, 0x00}, dstTSAP, 0x0A)
		if _, err := parseCR(cr); err != nil {
			t.Errorf("parseCR rejected dst-tsap % x: %v", dstTSAP, err)
		}
	}
}

func TestParseCRRejectsWrongType(t *testing.T) {
	cr := buildTestCR(1, []byte{0x01, 0x00}, []byte{0x03, 0x02}, 0x0A)
	cr[1] = cotpDT // corrupt the type byte
	if _, err := parseCR(cr); err == nil {
		t.Fatal("expected an error for a non-CR type byte, got nil")
	}
}

func TestParseCRDoesNotPanicOnTruncatedInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseCR panicked: %v", r)
		}
	}()
	full := buildTestCR(1, []byte{0x01, 0x00}, []byte{0x03, 0x02}, 0x0A)
	for n := 0; n < 8; n++ {
		if _, err := parseCR(full[:n]); err == nil {
			t.Errorf("parseCR accepted a truncated (%d-byte) CR", n)
		}
	}
}

func TestParseCRRejectsOversizedLI(t *testing.T) {
	cr := buildTestCR(1, []byte{0x01, 0x00}, []byte{0x03, 0x02}, 0x0A)
	cr[0] = 0xFF // claims a header far longer than the buffer actually holds
	if _, err := parseCR(cr); err == nil {
		t.Fatal("expected an error for an LI longer than the buffer, got nil")
	}
}

func TestDTRoundTrip(t *testing.T) {
	payload := []byte{0x32, 0x01, 0x00, 0x00}
	dt := buildDT(payload)
	if dt[0] != 0x02 || dt[1] != cotpDT || dt[2] != dtEOT {
		t.Fatalf("DT header = % x, want [02 f0 80]", dt[:3])
	}

	out, err := parseDT(dt)
	if err != nil {
		t.Fatalf("parseDT: %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("parseDT payload = % x, want % x", out, payload)
	}
}

func TestParseDTRejectsTruncatedAndMalformedInput(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x02},
		{0x02, 0xF0},             // missing the TPDU-NR/EOT byte
		{0x03, 0xF0, 0x80, 0x32}, // wrong LI
		{0x02, 0xE0, 0x80, 0x32}, // wrong type (looks like a CR)
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseDT panicked on % x: %v", c, r)
				}
			}()
			if _, err := parseDT(c); err == nil {
				t.Errorf("parseDT accepted malformed input % x", c)
			}
		}()
	}
}
