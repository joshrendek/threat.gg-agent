package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestSelectRDPProtocol(t *testing.T) {
	tests := []struct {
		name    string
		hasNeg  bool
		mask    uint32
		want    uint32
		wantErr bool
	}{
		{"absent negotiation", false, 0, protocolRDP, false},
		{"SSL only", true, protocolSSL, protocolSSL, false},
		{"Hybrid", true, protocolHybrid, protocolHybrid, false},
		{"Hybrid plus HybridEx", true, protocolHybrid | protocolHybridEx, protocolHybrid, false},
		{"HybridEx only", true, protocolHybridEx, 0, true},
		{"unsupported mask", true, 0x10, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectRDPProtocol(tt.hasNeg, tt.mask)
			if tt.wantErr {
				if !errors.Is(err, errRDPMalformed) {
					t.Fatalf("selectRDPProtocol() error = %v, want errRDPMalformed", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("selectRDPProtocol() = (%#x, %v), want (%#x, nil)", got, err, tt.want)
			}
		})
	}
}

func TestX224ProtocolSelectionPacketBytes(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   uint32
		err    bool
	}{
		{
			name:   "standard without negotiation",
			packet: []byte{6, x224TypeCR, 0, 0, 0, 0, 0},
			want:   protocolRDP,
		},
		{
			name:   "SSL",
			packet: []byte{14, x224TypeCR, 0, 0, 0, 0, 0, 1, 0, 8, 0, 1, 0, 0, 0},
			want:   protocolSSL,
		},
		{
			name:   "Hybrid",
			packet: []byte{14, x224TypeCR, 0, 0, 0, 0, 0, 1, 0, 8, 0, 2, 0, 0, 0},
			want:   protocolHybrid,
		},
		{
			name:   "HybridEx only is rejected",
			packet: []byte{14, x224TypeCR, 0, 0, 0, 0, 0, 1, 0, 8, 0, 8, 0, 0, 0},
			err:    true,
		},
		{
			name:   "unsupported",
			packet: []byte{14, x224TypeCR, 0, 0, 0, 0, 0, 1, 0, 8, 0, 16, 0, 0, 0},
			err:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := parseX224Request(tt.packet)
			if err != nil {
				t.Fatalf("parseX224Request() error = %v", err)
			}
			got, err := selectProtocol(*req)
			if tt.err {
				if !errors.Is(err, errRDPMalformed) {
					t.Fatalf("selectProtocol() error = %v, want errRDPMalformed", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("selectProtocol() = (%#x, %v), want (%#x, nil)", got, err, tt.want)
			}
		})
	}
}

func TestParseX224RequestLength(t *testing.T) {
	valid := []byte{6, x224TypeCR, 0, 0, 0, 0, 0}
	if _, err := parseX224Request(valid); err != nil {
		t.Fatalf("valid X.224 CR rejected: %v", err)
	}
	for name, packet := range map[string][]byte{
		"short":         {5, x224TypeCR, 0, 0, 0, 0},
		"mismatched LI": {7, x224TypeCR, 0, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseX224Request(packet); !errors.Is(err, errRDPMalformed) {
				t.Fatalf("parseX224Request() error = %v, want errRDPMalformed", err)
			}
		})
	}
}

func TestParseClientData(t *testing.T) {
	core := make([]byte, 56)
	binary.LittleEndian.PutUint16(core[0:2], csCore)
	binary.LittleEndian.PutUint16(core[2:4], uint16(len(core)))
	binary.LittleEndian.PutUint32(core[4:8], 0x00080004)
	binary.LittleEndian.PutUint16(core[8:10], 1920)
	binary.LittleEndian.PutUint16(core[10:12], 1080)
	binary.LittleEndian.PutUint32(core[16:20], 0x00000409)
	binary.LittleEndian.PutUint32(core[20:24], 19041)
	for i, r := range []byte("CLIENT") {
		binary.LittleEndian.PutUint16(core[24+i*2:], uint16(r))
	}

	net := make([]byte, 8+2*12)
	binary.LittleEndian.PutUint16(net[0:2], csNet)
	binary.LittleEndian.PutUint16(net[2:4], uint16(len(net)))
	binary.LittleEndian.PutUint16(net[4:6], 1003)
	binary.LittleEndian.PutUint16(net[6:8], 2)
	copy(net[8:16], []byte("rdpdr   "))
	binary.LittleEndian.PutUint32(net[16:20], 0x80800000)
	copy(net[20:28], []byte("cliprdr "))
	binary.LittleEndian.PutUint32(net[28:32], 0x80800000)

	got, err := parseClientData(append(core, net...))
	if err != nil {
		t.Fatal(err)
	}
	if got.Build != 19041 || got.Width != 1920 || got.Height != 1080 || got.KeyboardLayout != "en-US" || got.ClientName != "CLIENT" {
		t.Fatalf("parsed core data = %#v", got)
	}
	if !bytes.Equal([]byte(got.Channels[0]), []byte("rdpdr")) || len(got.Channels) != 2 || got.Channels[1] != "cliprdr" {
		t.Fatalf("parsed channels = %#v", got.Channels)
	}
}

func TestParseClientDataRejectsMalformedAndBoundedInputs(t *testing.T) {
	badLength := []byte{byte(csCore & 0xff), byte(csCore >> 8), 55, 0}
	if _, err := parseClientData(badLength); !errors.Is(err, errRDPMalformed) {
		t.Fatalf("bad declared length error = %v", err)
	}
	countTooLarge := make([]byte, 8)
	binary.LittleEndian.PutUint16(countTooLarge[0:2], csNet)
	binary.LittleEndian.PutUint16(countTooLarge[2:4], 8)
	binary.LittleEndian.PutUint16(countTooLarge[6:8], maxClientChannels+1)
	if _, err := parseClientData(countTooLarge); !errors.Is(err, errRDPTooLarge) {
		t.Fatalf("large channel count error = %v", err)
	}
	duplicate := make([]byte, 8+2*12)
	binary.LittleEndian.PutUint16(duplicate[0:2], csNet)
	binary.LittleEndian.PutUint16(duplicate[2:4], uint16(len(duplicate)))
	binary.LittleEndian.PutUint16(duplicate[6:8], 2)
	copy(duplicate[8:16], []byte("same    "))
	copy(duplicate[20:28], []byte("same    "))
	got, err := parseClientData(duplicate)
	if err != nil || len(got.Channels) != 1 {
		t.Fatalf("duplicate channels = %#v, error %v", got, err)
	}
	max := make([]byte, 8+maxClientChannels*12)
	binary.LittleEndian.PutUint16(max[0:2], csNet)
	binary.LittleEndian.PutUint16(max[2:4], uint16(len(max)))
	binary.LittleEndian.PutUint16(max[6:8], maxClientChannels)
	for i := 0; i < maxClientChannels; i++ {
		name := []byte{byte('a' + i/26), byte('a' + i%26)}
		copy(max[8+i*12:], name)
	}
	got, err = parseClientData(max)
	if err != nil || len(got.Channels) != maxClientChannels {
		t.Fatalf("max channels = %d, error %v", len(got.Channels), err)
	}
	if _, err := parseClientData(bytes.Repeat([]byte{0}, maxTPKTPayload+1)); !errors.Is(err, errRDPTooLarge) {
		t.Fatalf("oversized input error = %v", err)
	}
}
