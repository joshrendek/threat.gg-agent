package mqtt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadRemainingLength(t *testing.T) {
	v, err := readRemainingLength(bytes.NewReader([]byte{0x96, 0x01}))
	if err != nil {
		t.Fatalf("readRemainingLength returned error: %v", err)
	}
	if v != 150 {
		t.Fatalf("expected 150, got %d", v)
	}
}

func TestParseConnectPacket(t *testing.T) {
	payload := make([]byte, 0)
	payload = append(payload, encodeUTF8("MQTT")...)
	payload = append(payload, 0x04) // protocol level
	payload = append(payload, 0xC2) // username + password + clean session
	payload = append(payload, 0x00, 0x3C)
	payload = append(payload, encodeUTF8("client-123")...)
	payload = append(payload, encodeUTF8("attacker")...)
	payload = append(payload, encodeUTF8("secret")...)

	cd, err := parseConnectPacket(payload)
	if err != nil {
		t.Fatalf("parseConnectPacket returned error: %v", err)
	}
	if cd.clientID != "client-123" || cd.username != "attacker" || cd.password != "secret" {
		t.Fatalf("unexpected connect data: %+v", cd)
	}
	if cd.protocolName != "MQTT" || cd.protocolLevel != 4 || !cd.cleanSession || cd.keepAliveSecs != 60 {
		t.Fatalf("unexpected protocol flags: %+v", cd)
	}
}

func TestParseSubscribeCommand(t *testing.T) {
	payload := make([]byte, 0)
	payload = append(payload, 0x00, 0x01)              // packet id
	payload = append(payload, encodeUTF8("home/#")...) // topic 1
	payload = append(payload, 0x01)                    // qos
	payload = append(payload, encodeUTF8("factory/+/cmd")...)
	payload = append(payload, 0x00)

	cmd, err := parseSubscribeCommand(payload)
	if err != nil {
		t.Fatalf("parseSubscribeCommand returned error: %v", err)
	}
	if cmd != "SUBSCRIBE home/#,factory/+/cmd" {
		t.Fatalf("unexpected command: %s", cmd)
	}
}

func TestParsePublishCommand(t *testing.T) {
	payload := make([]byte, 0)
	payload = append(payload, encodeUTF8("home/thermostat/set")...)
	payload = append(payload, []byte(`{"target":21}`)...)

	cmd, err := parsePublishCommand(payload, 0)
	if err != nil {
		t.Fatalf("parsePublishCommand returned error: %v", err)
	}
	if cmd != "PUBLISH home/thermostat/set {\"target\":21}" {
		t.Fatalf("unexpected command: %s", cmd)
	}
}

func TestBuildPublishPacketRoundTrip(t *testing.T) {
	topic := "sensors/temperature"
	msg := "{\"temp\":22.3}"

	pkt := buildPublishPacket(topic, msg)
	fixed, payload, err := readPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("readPacket returned error: %v", err)
	}
	if fixed>>4 != packetTypePublish {
		t.Fatalf("expected publish packet type, got %d", fixed>>4)
	}

	cmd, err := parsePublishCommand(payload, fixed&0x0F)
	if err != nil {
		t.Fatalf("parsePublishCommand returned error: %v", err)
	}
	want := "PUBLISH " + topic + " " + msg
	if cmd != want {
		t.Fatalf("expected %q, got %q", want, cmd)
	}
}

func encodeUTF8(v string) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(v)))
	return append(buf, []byte(v)...)
}
