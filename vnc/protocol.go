package vnc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	protocolVersion                = "RFB 003.008\n"
	securityTypeNone          byte = 1
	securityTypeVNCAuth       byte = 2
	challengeLength                = 16
	clientMessageReadDeadline      = 1500 * time.Millisecond
	maxEncodingCount               = 256
)

var pixelFormat32bpp = []byte{
	32, 24, 0, 1, // bpp, depth, big-endian-flag, true-color-flag
	0, 255, 0, 255, 0, 255, // red/green/blue max
	16, 8, 0, // red/green/blue shift
	0, 0, 0, // padding
}

func writeProtocolVersion(w io.Writer) error {
	_, err := io.WriteString(w, protocolVersion)
	return err
}

func readProtocolVersion(r io.Reader) (string, error) {
	buf := make([]byte, len(protocolVersion))
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read client protocol version: %w", err)
	}

	version := string(buf)
	if !strings.HasPrefix(version, "RFB ") || !strings.HasSuffix(version, "\n") {
		return "", fmt.Errorf("invalid protocol version: %q", version)
	}
	return strings.TrimSpace(version), nil
}

func writeSecurityTypes(w io.Writer) error {
	// RFB 3.7+ format: number-of-types + types.
	_, err := w.Write([]byte{2, securityTypeNone, securityTypeVNCAuth})
	return err
}

func readSecuritySelection(r io.Reader) (byte, error) {
	var selected [1]byte
	if _, err := io.ReadFull(r, selected[:]); err != nil {
		return 0, fmt.Errorf("read selected security type: %w", err)
	}
	if selected[0] != securityTypeNone && selected[0] != securityTypeVNCAuth {
		return 0, fmt.Errorf("unsupported security type: %d", selected[0])
	}
	return selected[0], nil
}

func writeSecurityResult(w io.Writer, result uint32) error {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], result)
	_, err := w.Write(out[:])
	return err
}

func writeChallenge(w io.Writer, challenge []byte) error {
	if len(challenge) != challengeLength {
		return fmt.Errorf("challenge must be %d bytes", challengeLength)
	}
	_, err := w.Write(challenge)
	return err
}

func readChallengeResponse(r io.Reader) ([]byte, error) {
	resp := make([]byte, challengeLength)
	if _, err := io.ReadFull(r, resp); err != nil {
		return nil, fmt.Errorf("read VNC auth response: %w", err)
	}
	return resp, nil
}

func readSharedFlag(r io.Reader) (bool, error) {
	var flag [1]byte
	if _, err := io.ReadFull(r, flag[:]); err != nil {
		return false, fmt.Errorf("read ClientInit shared flag: %w", err)
	}
	return flag[0] != 0, nil
}

func writeServerInit(w io.Writer, name string) error {
	var out bytes.Buffer

	// Framebuffer size: 1024x768.
	_ = binary.Write(&out, binary.BigEndian, uint16(1024))
	_ = binary.Write(&out, binary.BigEndian, uint16(768))
	out.Write(pixelFormat32bpp)
	_ = binary.Write(&out, binary.BigEndian, uint32(len(name)))
	out.WriteString(name)

	_, err := w.Write(out.Bytes())
	return err
}

func readClientPreferences(conn net.Conn) (string, []int32, error) {
	if err := conn.SetReadDeadline(time.Now().Add(clientMessageReadDeadline)); err != nil {
		return "", nil, err
	}

	var pixelFormat string
	var encodings []int32

	for {
		var typ [1]byte
		if _, err := io.ReadFull(conn, typ[:]); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return pixelFormat, encodings, nil
			}
			if err == io.EOF {
				return pixelFormat, encodings, nil
			}
			return pixelFormat, encodings, err
		}

		switch typ[0] {
		case 0: // SetPixelFormat
			payload := make([]byte, 19) // 3 pad + 16 pixel format
			if _, err := io.ReadFull(conn, payload); err != nil {
				return pixelFormat, encodings, err
			}
			pf := payload[3:]
			pixelFormat = describePixelFormat(pf)
		case 2: // SetEncodings
			var header [3]byte // 1 pad + 2 count
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return pixelFormat, encodings, err
			}
			count := int(binary.BigEndian.Uint16(header[1:3]))
			if count > maxEncodingCount {
				return pixelFormat, encodings, fmt.Errorf("encoding count too large: %d", count)
			}
			encodings = make([]int32, count)
			for i := 0; i < count; i++ {
				var raw [4]byte
				if _, err := io.ReadFull(conn, raw[:]); err != nil {
					return pixelFormat, encodings, err
				}
				encodings[i] = int32(binary.BigEndian.Uint32(raw[:]))
			}
		default:
			// Ignore unknown messages. Common clients send more after SetEncodings.
			continue
		}
	}
}

func describePixelFormat(pf []byte) string {
	if len(pf) != 16 {
		return ""
	}
	return fmt.Sprintf(
		"bpp=%d depth=%d big_endian=%t true_color=%t red_max=%d green_max=%d blue_max=%d shifts=%d/%d/%d",
		pf[0], pf[1], pf[2] != 0, pf[3] != 0,
		binary.BigEndian.Uint16(pf[4:6]),
		binary.BigEndian.Uint16(pf[6:8]),
		binary.BigEndian.Uint16(pf[8:10]),
		pf[10], pf[11], pf[12],
	)
}
