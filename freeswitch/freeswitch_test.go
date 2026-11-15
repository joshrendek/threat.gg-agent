package freeswitch

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func sipRequest(method, to, body string) []byte {
	return []byte(method + " sip:pbx.example SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKsafe\r\n" +
		"From: <sip:caller@example.test>;tag=safe\r\n" +
		"To: <sip:" + to + "@example.test>\r\n" +
		"Call-ID: safe-call-id\r\n" +
		"CSeq: 7 " + method + "\r\n" +
		"Authorization: Digest username=\"must-not-persist\"\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: " + stringInt(len(body)) + "\r\n\r\n" + body)
}

func stringInt(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var result string
	for value > 0 {
		result = string(digits[value%10]) + result
		value /= 10
	}
	return result
}

func TestClassifyDangerousMESSAGEWithoutRetainingOrExecutingBody(t *testing.T) {
	const body = "api system touch /tmp/must-not-run-and-must-not-persist"
	event, reply, err := classify(sipRequest("MESSAGE", "api+system", body), "203.0.113.50:5060", 2)
	if err != nil {
		t.Fatal(err)
	}
	if event.Action != "sip_message_api_selector" || event.Cve != "CVE-2026-116779" || !event.AuthBypass || event.StatusCode != 403 {
		t.Fatalf("classification: %+v", event)
	}
	if event.Metadata["to_selector"] != "api_plus" || event.Metadata["auth_header_present"] != "true" || event.Metadata["transport_sequence"] != "2" {
		t.Fatalf("metadata: %+v", event.Metadata)
	}
	if !strings.Contains(reply, "403 Forbidden") || strings.Contains(event.String(), body) || strings.Contains(event.String(), "must-not-persist") {
		t.Fatalf("unsafe event or response: event=%+v response=%q", event, reply)
	}
}

func TestOrdinarySIPMethodsProduceRealisticSafeResponses(t *testing.T) {
	for _, test := range []struct {
		method, to, status string
	}{
		{"OPTIONS", "operator", "200 OK"},
		{"REGISTER", "operator", "401 Unauthorized"},
		{"MESSAGE", "operator", "202 Accepted"},
	} {
		event, reply, err := classify(sipRequest(test.method, test.to, "hello"), "198.51.100.2:5060", 1)
		if err != nil || event.Cve != "" || !strings.Contains(reply, test.status) {
			t.Fatalf("%s: event=%+v reply=%q err=%v", test.method, event, reply, err)
		}
	}
}

func TestReadMessageRejectsOversizedHeadersAndBodies(t *testing.T) {
	oversizedHeader := "MESSAGE sip:x SIP/2.0\r\nX-Fill: " + strings.Repeat("x", maxHeaderBytes) + "\r\n\r\n"
	if _, err := readMessage(bufio.NewReaderSize(strings.NewReader(oversizedHeader), maxHeaderBytes)); err == nil {
		t.Fatal("oversized header accepted")
	}
	oversizedBody := "MESSAGE sip:x SIP/2.0\r\nContent-Length: 65537\r\n\r\n"
	if _, err := readMessage(bufio.NewReader(strings.NewReader(oversizedBody))); err == nil {
		t.Fatal("oversized body accepted")
	}
	truncatedBody := "MESSAGE sip:x SIP/2.0\r\nContent-Length: 5\r\n\r\nxx"
	if _, err := readMessage(bufio.NewReader(strings.NewReader(truncatedBody))); err == nil {
		t.Fatal("truncated body accepted")
	}
}

func FuzzClassifySIP(f *testing.F) {
	f.Add(sipRequest("MESSAGE", "api+system", "fixture"))
	f.Add([]byte("OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > maxHeaderBytes+maxBodyBytes+1 {
			packet = packet[:maxHeaderBytes+maxBodyBytes+1]
		}
		event, response, err := classify(bytes.Clone(packet), "192.0.2.1:5060", 1)
		if err == nil && (event == nil || len(response) > 8192) {
			t.Fatalf("unbounded successful classification: event=%+v response=%d", event, len(response))
		}
	})
}
