package vnc

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadProtocolVersion(t *testing.T) {
	version, err := readProtocolVersion(bytes.NewBufferString(protocolVersion))
	require.NoError(t, err)
	require.Equal(t, "RFB 003.008", version)
}

func TestReadProtocolVersionInvalid(t *testing.T) {
	_, err := readProtocolVersion(bytes.NewBufferString("HELLO WORLD\n"))
	require.Error(t, err)
}

func TestReadSecuritySelection(t *testing.T) {
	selected, err := readSecuritySelection(bytes.NewBuffer([]byte{securityTypeVNCAuth}))
	require.NoError(t, err)
	require.Equal(t, securityTypeVNCAuth, selected)
}

func TestReadSecuritySelectionUnsupported(t *testing.T) {
	_, err := readSecuritySelection(bytes.NewBuffer([]byte{99}))
	require.Error(t, err)
}

func TestWriteServerInit(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, writeServerInit(&out, "threat.gg VNC"))

	packet := out.Bytes()
	require.GreaterOrEqual(t, len(packet), 24)
	require.Equal(t, uint16(1024), binary.BigEndian.Uint16(packet[0:2]))
	require.Equal(t, uint16(768), binary.BigEndian.Uint16(packet[2:4]))
	require.Equal(t, uint32(len("threat.gg VNC")), binary.BigEndian.Uint32(packet[20:24]))
	require.Equal(t, "threat.gg VNC", string(packet[24:]))
}

func TestReadClientPreferences(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// SetPixelFormat
		_, _ = client.Write([]byte{
			0x00,             // message type
			0x00, 0x00, 0x00, // padding
			32, 24, 0, 1, // pixel format start
			0, 255, 0, 255, 0, 255,
			16, 8, 0,
			0, 0, 0, // padding
		})

		// SetEncodings with 2 values: Raw(0), Tight(7)
		_, _ = client.Write([]byte{
			0x02,             // message type
			0x00, 0x00, 0x02, // padding + count
			0x00, 0x00, 0x00, 0x00, // raw
			0x00, 0x00, 0x00, 0x07, // tight
		})
		_ = client.SetDeadline(time.Now().Add(10 * time.Millisecond))
	}()

	pixelFormat, encodings, err := readClientPreferences(server)
	require.NoError(t, err)
	require.Contains(t, pixelFormat, "bpp=32")
	require.Equal(t, []int32{0, 7}, encodings)
	<-done
}
