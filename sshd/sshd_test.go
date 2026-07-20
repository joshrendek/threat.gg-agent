package sshd

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func execPayload(command string) []byte {
	payload := make([]byte, 4+len(command))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(command)))
	copy(payload[4:], command)
	return payload
}

func TestParseExecCommandUsesFullUint32Length(t *testing.T) {
	for _, size := range []int{0, 1, 255, 256, 511, 4096} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			command := strings.Repeat("x", size)
			got, err := parseExecCommand(execPayload(command))
			if err != nil {
				t.Fatalf("parseExecCommand(%d bytes): %v", size, err)
			}
			if got != command {
				t.Fatalf("parseExecCommand(%d bytes) returned %d bytes", size, len(got))
			}
		})
	}
}

func TestParseExecCommandRejectsMalformedPayloads(t *testing.T) {
	tests := map[string][]byte{
		"missing header": {0, 0, 0},
		"declared too long": func() []byte {
			payload := execPayload("short")
			binary.BigEndian.PutUint32(payload[:4], 100)
			return payload
		}(),
		"over limit": func() []byte {
			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, maxExecCommandLen+1)
			return payload
		}(),
	}

	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseExecCommand(payload); err == nil {
				t.Fatal("parseExecCommand returned nil error")
			}
		})
	}
}

func TestParseExecCommandIgnoresTrailingRequestBytes(t *testing.T) {
	payload := append(execPayload("uname -a"), []byte("trailing")...)
	got, err := parseExecCommand(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != "uname -a" {
		t.Fatalf("got %q", got)
	}
}
