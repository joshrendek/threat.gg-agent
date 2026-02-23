package kafka

import (
	"encoding/binary"
	"errors"
	"io"
)

// Kafka API keys
const (
	apiProduce         = 0
	apiFetch           = 1
	apiListOffsets     = 2
	apiMetadata        = 3
	apiFindCoordinator = 10
	apiSaslHandshake   = 17
	apiApiVersions     = 18
	apiSaslAuthenticate = 36
)

// apiKeyName maps API key numbers to human-readable names.
func apiKeyName(key int16) string {
	switch key {
	case apiProduce:
		return "Produce"
	case apiFetch:
		return "Fetch"
	case apiListOffsets:
		return "ListOffsets"
	case apiMetadata:
		return "Metadata"
	case apiFindCoordinator:
		return "FindCoordinator"
	case apiSaslHandshake:
		return "SaslHandshake"
	case apiApiVersions:
		return "ApiVersions"
	case apiSaslAuthenticate:
		return "SaslAuthenticate"
	default:
		return "Unknown"
	}
}

// requestHeader holds the parsed Kafka request header fields.
type requestHeader struct {
	ApiKey        int16
	ApiVersion    int16
	CorrelationID int32
	ClientID      string
}

// readRequest reads a single Kafka request frame from the connection.
// Returns the header and the remaining body bytes after the header.
func readRequest(r io.Reader) (*requestHeader, []byte, error) {
	// Read 4-byte size prefix
	var size int32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, nil, err
	}
	if size <= 0 || size > 10*1024*1024 { // 10MB sanity limit
		return nil, nil, errors.New("invalid request size")
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, nil, err
	}

	if len(buf) < 8 {
		return nil, nil, errors.New("request too short for header")
	}

	hdr := &requestHeader{
		ApiKey:        int16(binary.BigEndian.Uint16(buf[0:2])),
		ApiVersion:    int16(binary.BigEndian.Uint16(buf[2:4])),
		CorrelationID: int32(binary.BigEndian.Uint32(buf[4:8])),
	}

	offset := 8
	// Parse nullable ClientID string
	if offset+2 <= len(buf) {
		clientIDLen := int16(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
		if clientIDLen > 0 && offset+int(clientIDLen) <= len(buf) {
			hdr.ClientID = string(buf[offset : offset+int(clientIDLen)])
			offset += int(clientIDLen)
		}
	}

	var body []byte
	if offset < len(buf) {
		body = buf[offset:]
	}

	return hdr, body, nil
}

// writeResponse writes a Kafka response frame with the given correlation ID and payload.
func writeResponse(w io.Writer, correlationID int32, payload []byte) error {
	size := int32(4 + len(payload)) // 4 bytes for correlationID + payload
	if err := binary.Write(w, binary.BigEndian, size); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, correlationID); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// buildApiVersionsResponse returns ApiVersions response body listing supported API keys.
func buildApiVersionsResponse() []byte {
	type apiVersion struct {
		key    int16
		minVer int16
		maxVer int16
	}
	versions := []apiVersion{
		{apiProduce, 0, 3},
		{apiFetch, 0, 4},
		{apiListOffsets, 0, 1},
		{apiMetadata, 0, 2},
		{apiFindCoordinator, 0, 0},
		{apiSaslHandshake, 0, 1},
		{apiApiVersions, 0, 3},
		{apiSaslAuthenticate, 0, 0},
	}

	// error_code(2) + api_versions count(4) + entries + throttle_time(4)
	buf := make([]byte, 0, 256)

	// error_code: 0 (no error)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// array length
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(versions)))
	for _, v := range versions {
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.key))
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.minVer))
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.maxVer))
	}
	// throttle_time_ms: 0
	buf = binary.BigEndian.AppendUint32(buf, 0)

	return buf
}

// buildApiVersionsV3Response returns an ApiVersions v3+ response using the flexible encoding format.
// Flexible versions use compact arrays (varint N+1 count) and tagged fields.
func buildApiVersionsV3Response() []byte {
	type apiVersion struct {
		key    int16
		minVer int16
		maxVer int16
	}
	versions := []apiVersion{
		{apiProduce, 0, 3},
		{apiFetch, 0, 4},
		{apiListOffsets, 0, 1},
		{apiMetadata, 0, 2},
		{apiFindCoordinator, 0, 0},
		{apiSaslHandshake, 0, 1},
		{apiApiVersions, 0, 3},
		{apiSaslAuthenticate, 0, 0},
	}

	buf := make([]byte, 0, 256)

	// error_code: 0 (no error)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// compact array count: N+1
	buf = appendUvarint(buf, uint64(len(versions)+1))
	for _, v := range versions {
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.key))
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.minVer))
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.maxVer))
		buf = appendUvarint(buf, 0) // tagged fields
	}
	// throttle_time_ms: 0
	buf = binary.BigEndian.AppendUint32(buf, 0)
	// tagged fields
	buf = appendUvarint(buf, 0)

	return buf
}

// writeFlexibleResponse writes a Kafka response frame using the flexible header (v1).
// The flexible response header includes tagged_fields after the correlation ID.
func writeFlexibleResponse(w io.Writer, correlationID int32, payload []byte) error {
	// Header: correlation_id(4) + tagged_fields(varint 0 = 1 byte)
	headerSize := 4 + 1
	size := int32(headerSize + len(payload))
	if err := binary.Write(w, binary.BigEndian, size); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, correlationID); err != nil {
		return err
	}
	// tagged_fields: 0 (no tags)
	if _, err := w.Write([]byte{0}); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// Fake cluster configuration
const (
	clusterID = "threat-gg-kafka-cluster"
	brokerID  = 0
	brokerHost = "kafka-0.internal"
	brokerPort = 9092
)

// fakeTopics defines the realistic topics returned in Metadata responses.
var fakeTopics = []struct {
	name       string
	partitions int32
}{
	{"orders", 3},
	{"user-events", 3},
	{"payments", 3},
	{"logs", 6},
	{"metrics", 3},
}

// buildMetadataResponse returns a Metadata response with fake broker and topic info.
func buildMetadataResponse() []byte {
	buf := make([]byte, 0, 512)

	// Brokers array: count(4) + [node_id(4) + host(2+N) + port(4) + rack(nullable)]
	buf = binary.BigEndian.AppendUint32(buf, 1) // 1 broker
	buf = binary.BigEndian.AppendUint32(buf, uint32(brokerID))
	buf = appendString(buf, brokerHost)
	buf = binary.BigEndian.AppendUint32(buf, uint32(brokerPort))
	// rack (nullable string) — null for v1+
	buf = appendNullableString(buf, "", true)

	// Cluster ID (nullable string) — v2+
	buf = appendString(buf, clusterID)
	// Controller ID
	buf = binary.BigEndian.AppendUint32(buf, uint32(brokerID))

	// Topics array
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(fakeTopics)))
	for _, t := range fakeTopics {
		// error_code
		buf = binary.BigEndian.AppendUint16(buf, 0)
		// topic name
		buf = appendString(buf, t.name)
		// is_internal
		buf = append(buf, 0)
		// partitions array
		buf = binary.BigEndian.AppendUint32(buf, uint32(t.partitions))
		for p := int32(0); p < t.partitions; p++ {
			// error_code
			buf = binary.BigEndian.AppendUint16(buf, 0)
			// partition_id
			buf = binary.BigEndian.AppendUint32(buf, uint32(p))
			// leader
			buf = binary.BigEndian.AppendUint32(buf, uint32(brokerID))
			// replicas: [brokerID]
			buf = binary.BigEndian.AppendUint32(buf, 1)
			buf = binary.BigEndian.AppendUint32(buf, uint32(brokerID))
			// isr: [brokerID]
			buf = binary.BigEndian.AppendUint32(buf, 1)
			buf = binary.BigEndian.AppendUint32(buf, uint32(brokerID))
		}
	}

	return buf
}

// buildProduceResponse returns a Produce response acknowledging the request.
func buildProduceResponse(body []byte) []byte {
	buf := make([]byte, 0, 128)

	// Parse enough of the produce request to build the response.
	// We need: acks (skip transactional_id in v3+), then topic count and names.
	// For simplicity, return a single topic/partition ack.
	// responses array count
	buf = binary.BigEndian.AppendUint32(buf, 1)
	// topic name — use first fake topic as fallback
	topicName := "unknown"
	if len(body) >= 6 {
		// body starts after header: acks(2) + timeout(4) + topics...
		// For v0-v2: acks(2) + timeout(4) + array_count(4) + topic_string
		offset := 6 // skip acks + timeout
		if offset+4 <= len(body) {
			offset += 4 // skip array count
			if offset+2 <= len(body) {
				tLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
				offset += 2
				if tLen > 0 && offset+tLen <= len(body) {
					topicName = string(body[offset : offset+tLen])
				}
			}
		}
	}
	buf = appendString(buf, topicName)
	// partition_responses count
	buf = binary.BigEndian.AppendUint32(buf, 1)
	// partition(4) + error_code(2) + base_offset(8)
	buf = binary.BigEndian.AppendUint32(buf, 0)  // partition 0
	buf = binary.BigEndian.AppendUint16(buf, 0)  // no error
	buf = binary.BigEndian.AppendUint64(buf, 0)  // base offset 0

	return buf
}

// buildFetchResponse returns an empty Fetch response.
func buildFetchResponse() []byte {
	buf := make([]byte, 0, 32)

	// throttle_time_ms
	buf = binary.BigEndian.AppendUint32(buf, 0)
	// responses array: empty
	buf = binary.BigEndian.AppendUint32(buf, 0)

	return buf
}

// buildFindCoordinatorResponse returns self as the coordinator.
func buildFindCoordinatorResponse() []byte {
	buf := make([]byte, 0, 64)

	// error_code
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// coordinator: node_id(4) + host(2+N) + port(4)
	buf = binary.BigEndian.AppendUint32(buf, uint32(brokerID))
	buf = appendString(buf, brokerHost)
	buf = binary.BigEndian.AppendUint32(buf, uint32(brokerPort))

	return buf
}

// buildSaslHandshakeResponse returns PLAIN as the only supported SASL mechanism.
func buildSaslHandshakeResponse() []byte {
	buf := make([]byte, 0, 32)

	// error_code: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// mechanisms array
	buf = binary.BigEndian.AppendUint32(buf, 1)
	buf = appendString(buf, "PLAIN")

	return buf
}

// buildSaslAuthenticateResponse returns a successful SASL authenticate response.
func buildSaslAuthenticateResponse() []byte {
	buf := make([]byte, 0, 16)

	// error_code: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// error_message (nullable): -1 (null)
	buf = binary.BigEndian.AppendUint16(buf, 0xFFFF)
	// auth_bytes: empty
	buf = binary.BigEndian.AppendUint32(buf, 0)

	return buf
}

// parseSaslPlain extracts username and password from a SASL/PLAIN auth payload.
// SASL/PLAIN format: \x00<authzid>\x00<username>\x00<password>
// The auth_bytes in SaslAuthenticate request: length(4) + data
func parseSaslPlain(body []byte) (username, password string) {
	if len(body) < 4 {
		return "", ""
	}
	authLen := int(binary.BigEndian.Uint32(body[0:4]))
	if authLen <= 0 || 4+authLen > len(body) {
		return "", ""
	}
	data := body[4 : 4+authLen]

	// Split on NUL bytes: authzid\0username\0password
	parts := splitNull(data)
	if len(parts) >= 3 {
		return parts[1], parts[2]
	}
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

// splitNull splits a byte slice on NUL bytes.
func splitNull(data []byte) []string {
	var parts []string
	start := 0
	for i, b := range data {
		if b == 0 {
			parts = append(parts, string(data[start:i]))
			start = i + 1
		}
	}
	if start <= len(data) {
		parts = append(parts, string(data[start:]))
	}
	return parts
}

// buildListOffsetsResponse returns offsets for requested topics.
func buildListOffsetsResponse() []byte {
	buf := make([]byte, 0, 64)

	// responses array: empty (no topics matched)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	return buf
}

// appendString appends a Kafka-style string (int16 length + bytes) to buf.
func appendString(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(s)))
	return append(buf, s...)
}

// appendNullableString appends a Kafka nullable string. Use length -1 for null.
func appendNullableString(buf []byte, s string, isNull bool) []byte {
	if isNull {
		return binary.BigEndian.AppendUint16(buf, 0xFFFF) // -1 as int16
	}
	return appendString(buf, s)
}

// appendUvarint appends an unsigned variable-length integer (used in flexible versions).
func appendUvarint(buf []byte, v uint64) []byte {
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], v)
	return append(buf, tmp[:n]...)
}

// appendCompactString appends a compact string (varint length+1, then bytes).
func appendCompactString(buf []byte, s string) []byte {
	buf = appendUvarint(buf, uint64(len(s)+1))
	return append(buf, s...)
}

// appendCompactNullableString appends a compact nullable string (0 for null, len+1 otherwise).
func appendCompactNullableString(buf []byte, s string, isNull bool) []byte {
	if isNull {
		return appendUvarint(buf, 0)
	}
	return appendCompactString(buf, s)
}
