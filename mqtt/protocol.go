package mqtt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	packetTypeConnect    = 1
	packetTypePublish    = 3
	packetTypeSubscribe  = 8
	packetTypePingReq    = 12
	packetTypeDisconnect = 14
)

var errMalformedPacket = errors.New("malformed mqtt packet")

type connectData struct {
	clientID      string
	username      string
	password      string
	protocolName  string
	protocolLevel int
	cleanSession  bool
	keepAliveSecs int
}

func readPacket(r io.Reader) (byte, []byte, error) {
	fixed := []byte{0}
	if _, err := io.ReadFull(r, fixed); err != nil {
		return 0, nil, err
	}

	remaining, err := readRemainingLength(r)
	if err != nil {
		return 0, nil, err
	}

	payload := make([]byte, remaining)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return fixed[0], payload, nil
}

func readRemainingLength(r io.Reader) (int, error) {
	multiplier := 1
	value := 0
	for i := 0; i < 4; i++ {
		encoded := []byte{0}
		if _, err := io.ReadFull(r, encoded); err != nil {
			return 0, err
		}
		value += int(encoded[0]&127) * multiplier
		if encoded[0]&128 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, errMalformedPacket
}

func parseConnectPacket(payload []byte) (*connectData, error) {
	r := bytes.NewReader(payload)

	protocolName, err := readUTF8(r)
	if err != nil {
		return nil, err
	}
	protocolLevel, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	connectFlags, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if connectFlags&0x01 == 0x01 {
		return nil, errMalformedPacket
	}

	keepAlive, err := readUint16(r)
	if err != nil {
		return nil, err
	}

	if protocolLevel == 5 {
		propLen, err := readRemainingLength(r)
		if err != nil {
			return nil, err
		}
		if propLen > r.Len() {
			return nil, errMalformedPacket
		}
		if _, err := r.Seek(int64(propLen), io.SeekCurrent); err != nil {
			return nil, err
		}
	}

	clientID, err := readUTF8(r)
	if err != nil {
		return nil, err
	}

	if connectFlags&0x04 != 0 {
		if _, err := readUTF8(r); err != nil {
			return nil, err
		}
		if connectFlags&0x20 != 0 {
			if _, err := readUTF8(r); err != nil {
				return nil, err
			}
		}
		if connectFlags&0x18 != 0 {
			if _, err := readUTF8(r); err != nil {
				return nil, err
			}
		}
	}

	username := ""
	if connectFlags&0x80 != 0 {
		username, err = readUTF8(r)
		if err != nil {
			return nil, err
		}
	}

	password := ""
	if connectFlags&0x40 != 0 {
		password, err = readUTF8(r)
		if err != nil {
			return nil, err
		}
	}

	return &connectData{
		clientID:      clientID,
		username:      username,
		password:      password,
		protocolName:  protocolName,
		protocolLevel: int(protocolLevel),
		cleanSession:  connectFlags&0x02 != 0,
		keepAliveSecs: int(keepAlive),
	}, nil
}

func parseSubscribeCommand(payload []byte) (string, error) {
	r := bytes.NewReader(payload)
	if _, err := readUint16(r); err != nil {
		return "", err
	}

	topics := make([]string, 0)
	for r.Len() > 0 {
		topic, err := readUTF8(r)
		if err != nil {
			return "", err
		}
		topics = append(topics, topic)

		if _, err := r.ReadByte(); err != nil {
			return "", err
		}
	}
	if len(topics) == 0 {
		return "", errMalformedPacket
	}
	return fmt.Sprintf("SUBSCRIBE %s", strings.Join(topics, ",")), nil
}

func parsePublishCommand(payload []byte, flags byte) (string, error) {
	r := bytes.NewReader(payload)
	topic, err := readUTF8(r)
	if err != nil {
		return "", err
	}

	qos := (flags >> 1) & 0x03
	if qos > 0 {
		if _, err := readUint16(r); err != nil {
			return "", err
		}
	}

	msg := string(payload[len(payload)-r.Len():])
	return fmt.Sprintf("PUBLISH %s %s", topic, msg), nil
}

func buildConnAck(protocolLevel int) []byte {
	if protocolLevel == 5 {
		return []byte{0x20, 0x03, 0x00, 0x00, 0x00}
	}
	return []byte{0x20, 0x02, 0x00, 0x00}
}

func buildPublishPacket(topic, msg string) []byte {
	topicLen := make([]byte, 2)
	binary.BigEndian.PutUint16(topicLen, uint16(len(topic)))
	variable := append(topicLen, []byte(topic)...)
	variable = append(variable, []byte(msg)...)

	rem := encodeRemainingLength(len(variable))
	packet := []byte{0x30}
	packet = append(packet, rem...)
	packet = append(packet, variable...)
	return packet
}

func encodeRemainingLength(n int) []byte {
	encoded := make([]byte, 0, 4)
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		encoded = append(encoded, digit)
		if n == 0 {
			break
		}
	}
	return encoded
}

func readUTF8(r *bytes.Reader) (string, error) {
	length, err := readUint16(r)
	if err != nil {
		return "", err
	}
	if int(length) > r.Len() {
		return "", errMalformedPacket
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readUint16(r *bytes.Reader) (uint16, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf), nil
}
