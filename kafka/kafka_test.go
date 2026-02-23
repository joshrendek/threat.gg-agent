package kafka

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestProtocolHandshake verifies the honeypot responds correctly to
// ApiVersions and Metadata requests (the minimum for kcat -L).
func TestProtocolHandshake(t *testing.T) {
	// Start a listener on a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	t.Logf("honeypot listening on %s", addr)

	// Accept one connection in background
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Process requests
		for i := 0; i < 3; i++ {
			hdr, body, err := readRequest(conn)
			if err != nil {
				if err == io.EOF {
					break
				}
				done <- err
				return
			}

			var resp []byte
			switch hdr.ApiKey {
			case apiApiVersions:
				resp = buildApiVersionsResponse()
			case apiMetadata:
				resp = buildMetadataResponse()
			case apiSaslHandshake:
				resp = buildSaslHandshakeResponse()
			case apiSaslAuthenticate:
				parseSaslPlain(body)
				resp = buildSaslAuthenticateResponse()
			default:
				resp = []byte{0, 35} // UNSUPPORTED_VERSION
			}

			if err := writeResponse(conn, hdr.CorrelationID, resp); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	// Connect as client
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send ApiVersions request (ApiKey=18, ApiVersion=1, CorrelationId=1, ClientId="test-client")
	t.Run("ApiVersions", func(t *testing.T) {
		resp := sendRequest(t, conn, 18, 1, 1, "test-client", nil)
		if len(resp) < 6 {
			t.Fatalf("ApiVersions response too short: %d bytes", len(resp))
		}
		errorCode := int16(binary.BigEndian.Uint16(resp[0:2]))
		if errorCode != 0 {
			t.Fatalf("expected error_code 0, got %d", errorCode)
		}
		apiCount := binary.BigEndian.Uint32(resp[2:6])
		if apiCount < 5 {
			t.Fatalf("expected at least 5 API versions, got %d", apiCount)
		}
		t.Logf("ApiVersions: %d APIs supported", apiCount)
	})

	// Send Metadata request (ApiKey=3, ApiVersion=1, CorrelationId=2)
	t.Run("Metadata", func(t *testing.T) {
		// Empty topic list = all topics
		body := make([]byte, 4)
		binary.BigEndian.PutUint32(body, 0) // 0 topics = list all
		resp := sendRequest(t, conn, 3, 1, 2, "test-client", body)
		if len(resp) < 4 {
			t.Fatalf("Metadata response too short: %d bytes", len(resp))
		}
		brokerCount := binary.BigEndian.Uint32(resp[0:4])
		if brokerCount != 1 {
			t.Fatalf("expected 1 broker, got %d", brokerCount)
		}
		t.Logf("Metadata: %d brokers, response %d bytes", brokerCount, len(resp))
	})

	// Wait for server goroutine
	select {
	case err := <-done:
		if err != nil {
			t.Logf("server error (may be expected): %v", err)
		}
	case <-time.After(3 * time.Second):
		// OK - server may be waiting for more requests
	}
}

// TestSaslPlainParsing verifies SASL/PLAIN credential extraction.
func TestSaslPlainParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantUser string
		wantPass string
	}{
		{
			name:     "standard PLAIN",
			input:    buildSaslPlainPayload("", "admin", "password123"),
			wantUser: "admin",
			wantPass: "password123",
		},
		{
			name:     "with authzid",
			input:    buildSaslPlainPayload("authz", "user", "secret"),
			wantUser: "user",
			wantPass: "secret",
		},
		{
			name:     "empty payload",
			input:    []byte{0, 0, 0, 0},
			wantUser: "",
			wantPass: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, pass := parseSaslPlain(tc.input)
			if user != tc.wantUser {
				t.Errorf("username: got %q, want %q", user, tc.wantUser)
			}
			if pass != tc.wantPass {
				t.Errorf("password: got %q, want %q", pass, tc.wantPass)
			}
		})
	}
}

// sendRequest sends a Kafka request frame and reads the response payload.
func sendRequest(t *testing.T, conn net.Conn, apiKey, apiVersion int16, correlationID int32, clientID string, body []byte) []byte {
	t.Helper()

	// Build request: ApiKey(2) + ApiVersion(2) + CorrelationId(4) + ClientId(2+N) + body
	var payload []byte
	payload = binary.BigEndian.AppendUint16(payload, uint16(apiKey))
	payload = binary.BigEndian.AppendUint16(payload, uint16(apiVersion))
	payload = binary.BigEndian.AppendUint32(payload, uint32(correlationID))
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(clientID)))
	payload = append(payload, clientID...)
	if body != nil {
		payload = append(payload, body...)
	}

	// Write size-prefixed frame
	size := int32(len(payload))
	if err := binary.Write(conn, binary.BigEndian, size); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	// Read response: size(4) + correlationId(4) + payload
	var respSize int32
	if err := binary.Read(conn, binary.BigEndian, &respSize); err != nil {
		t.Fatal(err)
	}
	respBuf := make([]byte, respSize)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatal(err)
	}

	// Verify correlation ID
	gotCorr := int32(binary.BigEndian.Uint32(respBuf[0:4]))
	if gotCorr != correlationID {
		t.Fatalf("correlation ID mismatch: got %d, want %d", gotCorr, correlationID)
	}

	return respBuf[4:] // skip correlation ID, return payload
}

// buildSaslPlainPayload creates a SASL/PLAIN auth payload with length prefix.
func buildSaslPlainPayload(authzid, username, password string) []byte {
	// SASL PLAIN: authzid\0username\0password
	plain := authzid + "\x00" + username + "\x00" + password
	buf := make([]byte, 4+len(plain))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(plain)))
	copy(buf[4:], plain)
	return buf
}
