package kafka

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Kafka API keys
const (
	apiProduce          = 0
	apiFetch            = 1
	apiListOffsets      = 2
	apiMetadata         = 3
	apiOffsetCommit     = 8
	apiOffsetFetch      = 9
	apiFindCoordinator  = 10
	apiJoinGroup        = 11
	apiHeartbeat        = 12
	apiLeaveGroup       = 13
	apiSyncGroup        = 14
	apiDescribeGroups   = 15
	apiListGroups       = 16
	apiSaslHandshake    = 17
	apiApiVersions      = 18
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
	case apiOffsetCommit:
		return "OffsetCommit"
	case apiOffsetFetch:
		return "OffsetFetch"
	case apiFindCoordinator:
		return "FindCoordinator"
	case apiJoinGroup:
		return "JoinGroup"
	case apiHeartbeat:
		return "Heartbeat"
	case apiLeaveGroup:
		return "LeaveGroup"
	case apiSyncGroup:
		return "SyncGroup"
	case apiDescribeGroups:
		return "DescribeGroups"
	case apiListGroups:
		return "ListGroups"
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
		{apiOffsetCommit, 0, 2},
		{apiOffsetFetch, 0, 1},
		{apiFindCoordinator, 0, 0},
		{apiJoinGroup, 0, 1},
		{apiHeartbeat, 0, 0},
		{apiLeaveGroup, 0, 0},
		{apiSyncGroup, 0, 0},
		{apiDescribeGroups, 0, 0},
		{apiListGroups, 0, 0},
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
		{apiOffsetCommit, 0, 2},
		{apiOffsetFetch, 0, 1},
		{apiFindCoordinator, 0, 0},
		{apiJoinGroup, 0, 1},
		{apiHeartbeat, 0, 0},
		{apiLeaveGroup, 0, 0},
		{apiSyncGroup, 0, 0},
		{apiDescribeGroups, 0, 0},
		{apiListGroups, 0, 0},
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

// fakeTopics defines enticing topics returned in Metadata responses.
// Security-themed names encourage attackers to attempt Fetch operations.
var fakeTopics = []struct {
	name       string
	partitions int32
}{
	{"internal-credentials", 3},
	{"user-sessions", 3},
	{"payment-events", 6},
	{"api-keys", 3},
	{"admin-notifications", 3},
	{"pii-exports", 3},
	{"audit-log", 6},
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

// messagesPerFetch is how many messages we serve per Fetch request.
const messagesPerFetch = 5

// buildFetchResponse returns a Fetch response with fake messages from the corpus.
// v0 request: replica_id(4) + max_wait(4) + min_bytes(4) + topics[name + partitions[partition(4) + fetch_offset(8) + max_bytes(4)]]
func buildFetchResponse(sess *session, body []byte) []byte {
	if sess.fetchOffsets == nil {
		sess.fetchOffsets = make(map[string]int64)
	}

	// Parse the Fetch request to get topics/partitions/offsets
	type fetchPartition struct {
		partition   int32
		fetchOffset int64
	}
	type fetchTopic struct {
		name       string
		partitions []fetchPartition
	}

	var topics []fetchTopic
	off := 12 // skip replica_id(4) + max_wait(4) + min_bytes(4)
	if off+4 <= len(body) {
		topicCount := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		for i := 0; i < topicCount && off+2 <= len(body); i++ {
			tLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			name := ""
			if tLen > 0 && off+tLen <= len(body) {
				name = string(body[off : off+tLen])
				off += tLen
			}
			ft := fetchTopic{name: name}
			if off+4 <= len(body) {
				pCount := int(binary.BigEndian.Uint32(body[off : off+4]))
				off += 4
				for j := 0; j < pCount && off+16 <= len(body); j++ {
					fp := fetchPartition{
						partition:   int32(binary.BigEndian.Uint32(body[off : off+4])),
						fetchOffset: int64(binary.BigEndian.Uint64(body[off+4 : off+12])),
					}
					off += 16 // partition(4) + fetch_offset(8) + max_bytes(4)
					ft.partitions = append(ft.partitions, fp)
				}
			}
			topics = append(topics, ft)
		}
	}

	buf := make([]byte, 0, 4096)
	// throttle_time_ms
	buf = binary.BigEndian.AppendUint32(buf, 0)
	// responses array
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(topics)))

	for _, t := range topics {
		buf = appendString(buf, t.name)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(t.partitions)))

		msgs := fakeMessages[t.name]
		for _, p := range t.partitions {
			buf = binary.BigEndian.AppendUint32(buf, uint32(p.partition))

			if msgs == nil {
				// Unknown topic — error code 3
				buf = binary.BigEndian.AppendUint16(buf, 3) // UNKNOWN_TOPIC_OR_PARTITION
				buf = binary.BigEndian.AppendUint64(buf, 0) // high watermark
				buf = binary.BigEndian.AppendUint32(buf, 0) // empty message set
				continue
			}

			buf = binary.BigEndian.AppendUint16(buf, 0)                      // no error
			buf = binary.BigEndian.AppendUint64(buf, uint64(len(msgs)))      // high watermark

			// Build message set
			startOffset := p.fetchOffset
			if startOffset < 0 {
				startOffset = 0
			}
			// Track offset in session (use request offset, or session state)
			key := fmt.Sprintf("%s-%d", t.name, p.partition)
			if startOffset == 0 {
				if sessOff, ok := sess.fetchOffsets[key]; ok {
					startOffset = sessOff
				}
			}

			var messageSet []byte
			count := 0
			for i := startOffset; i < startOffset+messagesPerFetch && i < int64(len(msgs)); i++ {
				idx := i % int64(len(msgs)) // wrap around
				messageSet = append(messageSet, buildMessageV0(i, nil, msgs[idx])...)
				count++
			}
			sess.fetchOffsets[key] = startOffset + int64(count)

			buf = binary.BigEndian.AppendUint32(buf, uint32(len(messageSet)))
			buf = append(buf, messageSet...)
		}
	}

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

// knownTopic returns true if the topic name matches one of our fakeTopics.
func knownTopic(name string) bool {
	for _, t := range fakeTopics {
		if t.name == name {
			return true
		}
	}
	return false
}

// topicPartitions returns the partition count for a known topic, or 0 if unknown.
func topicPartitions(name string) int32 {
	for _, t := range fakeTopics {
		if t.name == name {
			return t.partitions
		}
	}
	return 0
}

// buildListOffsetsResponse parses the ListOffsets request and returns real offsets.
// v0: replica_id(4) + topics[name + partitions[partition(4) + timestamp(8) + max_offsets(4)]]
// v1: replica_id(4) + topics[name + partitions[partition(4) + timestamp(8)]]
// timestamp -1 = latest, -2 = earliest.
func buildListOffsetsResponse(body []byte, version int16) []byte {
	type partReq struct {
		partition int32
		timestamp int64
	}
	type topicReq struct {
		name       string
		partitions []partReq
	}

	var topics []topicReq
	off := 4 // skip replica_id
	if off+4 <= len(body) {
		topicCount := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		for i := 0; i < topicCount && off+2 <= len(body); i++ {
			tLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			name := ""
			if tLen > 0 && off+tLen <= len(body) {
				name = string(body[off : off+tLen])
				off += tLen
			}
			tr := topicReq{name: name}
			if off+4 <= len(body) {
				pCount := int(binary.BigEndian.Uint32(body[off : off+4]))
				off += 4
				for j := 0; j < pCount && off+12 <= len(body); j++ {
					p := partReq{
						partition: int32(binary.BigEndian.Uint32(body[off : off+4])),
						timestamp: int64(binary.BigEndian.Uint64(body[off+4 : off+12])),
					}
					off += 12
					if version == 0 {
						off += 4 // skip max_num_offsets
					}
					tr.partitions = append(tr.partitions, p)
				}
			}
			topics = append(topics, tr)
		}
	}

	buf := make([]byte, 0, 256)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(topics)))
	for _, t := range topics {
		buf = appendString(buf, t.name)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(t.partitions)))
		for _, p := range t.partitions {
			buf = binary.BigEndian.AppendUint32(buf, uint32(p.partition))
			if !knownTopic(t.name) {
				// error_code 3 = UNKNOWN_TOPIC_OR_PARTITION
				buf = binary.BigEndian.AppendUint16(buf, 3)
				if version == 0 {
					buf = binary.BigEndian.AppendUint32(buf, 0) // empty old_style offsets array
				} else {
					buf = binary.BigEndian.AppendUint64(buf, 0xFFFFFFFFFFFFFFFF) // timestamp -1
					buf = binary.BigEndian.AppendUint64(buf, 0xFFFFFFFFFFFFFFFF) // offset -1
				}
			} else {
				buf = binary.BigEndian.AppendUint16(buf, 0) // no error
				var offset int64
				if p.timestamp == -2 { // earliest
					offset = 0
				} else { // latest (-1) or specific timestamp
					offset = messagesPerTopic
				}
				if version == 0 {
					// v0: old_style_offsets array
					buf = binary.BigEndian.AppendUint32(buf, 1) // array of 1
					buf = binary.BigEndian.AppendUint64(buf, uint64(offset))
				} else {
					// v1+: timestamp + offset
					buf = binary.BigEndian.AppendUint64(buf, uint64(p.timestamp))
					buf = binary.BigEndian.AppendUint64(buf, uint64(offset))
				}
			}
		}
	}
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

// --- Consumer Group API builders ---

// parseJoinGroupRequest extracts group_id, session_timeout, and protocol info.
// v0: group_id(str) + session_timeout(4) + member_id(str) + protocol_type(str) + protocols[name(str) + metadata(bytes)]
// v1: adds rebalance_timeout(4) after session_timeout
func parseJoinGroupRequest(body []byte, version int16) (groupID string, sessionTimeout int32, memberID string, protocolType string, protocols []string) {
	off := 0
	// group_id
	if off+2 > len(body) {
		return
	}
	gLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if gLen > 0 && off+gLen <= len(body) {
		groupID = string(body[off : off+gLen])
		off += gLen
	}
	// session_timeout
	if off+4 > len(body) {
		return
	}
	sessionTimeout = int32(binary.BigEndian.Uint32(body[off : off+4]))
	off += 4
	// rebalance_timeout (v1+)
	if version >= 1 {
		off += 4
	}
	// member_id
	if off+2 > len(body) {
		return
	}
	mLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if mLen > 0 && off+mLen <= len(body) {
		memberID = string(body[off : off+mLen])
		off += mLen
	}
	// protocol_type
	if off+2 > len(body) {
		return
	}
	ptLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if ptLen > 0 && off+ptLen <= len(body) {
		protocolType = string(body[off : off+ptLen])
		off += ptLen
	}
	// group_protocols array
	if off+4 > len(body) {
		return
	}
	pCount := int(binary.BigEndian.Uint32(body[off : off+4]))
	off += 4
	for i := 0; i < pCount && off+2 <= len(body); i++ {
		nLen := int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2
		if nLen > 0 && off+nLen <= len(body) {
			protocols = append(protocols, string(body[off:off+nLen]))
			off += nLen
		}
		// skip metadata bytes
		if off+4 <= len(body) {
			bLen := int(binary.BigEndian.Uint32(body[off : off+4]))
			off += 4
			if bLen > 0 {
				off += bLen
			}
		}
	}
	return
}

// buildJoinGroupResponse assigns the attacker as sole leader of the group.
func buildJoinGroupResponse(sess *session, groupID, memberID string, generation int32) []byte {
	buf := make([]byte, 0, 256)

	// error_code: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// generation_id
	buf = binary.BigEndian.AppendUint32(buf, uint32(generation))
	// group_protocol (assigned strategy)
	buf = appendString(buf, "range")
	// leader (this member is the leader)
	buf = appendString(buf, memberID)
	// member_id
	buf = appendString(buf, memberID)
	// members array: 1 member (the attacker)
	buf = binary.BigEndian.AppendUint32(buf, 1)
	// member_id
	buf = appendString(buf, memberID)
	// member_metadata: ConsumerProtocol subscription
	meta := buildConsumerSubscription()
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(meta)))
	buf = append(buf, meta...)

	return buf
}

// buildConsumerSubscription builds a ConsumerProtocol Subscription with all fake topics.
func buildConsumerSubscription() []byte {
	buf := make([]byte, 0, 128)
	// version: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// topics array
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(fakeTopics)))
	for _, t := range fakeTopics {
		buf = appendString(buf, t.name)
	}
	// user_data: null (-1)
	buf = binary.BigEndian.AppendUint32(buf, 0xFFFFFFFF)
	return buf
}

// buildSyncGroupResponse returns a ConsumerAssignment giving all partitions of all fake topics.
func buildSyncGroupResponse() []byte {
	buf := make([]byte, 0, 256)

	// error_code: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// member_assignment bytes
	assignment := buildConsumerAssignment()
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(assignment)))
	buf = append(buf, assignment...)

	return buf
}

// buildConsumerAssignment builds a ConsumerProtocol Assignment with all partitions.
func buildConsumerAssignment() []byte {
	buf := make([]byte, 0, 256)
	// version: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// topic_partitions array
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(fakeTopics)))
	for _, t := range fakeTopics {
		buf = appendString(buf, t.name)
		buf = binary.BigEndian.AppendUint32(buf, uint32(t.partitions))
		for p := int32(0); p < t.partitions; p++ {
			buf = binary.BigEndian.AppendUint32(buf, uint32(p))
		}
	}
	// user_data: null (-1)
	buf = binary.BigEndian.AppendUint32(buf, 0xFFFFFFFF)
	return buf
}

// parseSyncGroupRequest extracts group_id, generation_id, and member_id from a SyncGroup request.
func parseSyncGroupRequest(body []byte) (groupID string, generationID int32, memberID string) {
	off := 0
	if off+2 > len(body) {
		return
	}
	gLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if gLen > 0 && off+gLen <= len(body) {
		groupID = string(body[off : off+gLen])
		off += gLen
	}
	if off+4 > len(body) {
		return
	}
	generationID = int32(binary.BigEndian.Uint32(body[off : off+4]))
	off += 4
	if off+2 > len(body) {
		return
	}
	mLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if mLen > 0 && off+mLen <= len(body) {
		memberID = string(body[off : off+mLen])
	}
	return
}

// buildHeartbeatResponse returns a success heartbeat response.
func buildHeartbeatResponse() []byte {
	// error_code: 0
	return []byte{0, 0}
}

// parseHeartbeatRequest extracts group_id, generation_id, and member_id.
func parseHeartbeatRequest(body []byte) (groupID string, generationID int32, memberID string) {
	return parseSyncGroupRequest(body) // same wire format for the first 3 fields
}

// buildLeaveGroupResponse returns a success leave group response.
func buildLeaveGroupResponse() []byte {
	// error_code: 0
	return []byte{0, 0}
}

// parseLeaveGroupRequest extracts group_id and member_id.
func parseLeaveGroupRequest(body []byte) (groupID, memberID string) {
	off := 0
	if off+2 > len(body) {
		return
	}
	gLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if gLen > 0 && off+gLen <= len(body) {
		groupID = string(body[off : off+gLen])
		off += gLen
	}
	if off+2 > len(body) {
		return
	}
	mLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if mLen > 0 && off+mLen <= len(body) {
		memberID = string(body[off : off+mLen])
	}
	return
}

// buildOffsetFetchResponse returns offset=-1 (no committed offset) for all requested partitions.
// v0: topics[name + partitions[partition(4) + offset(8) + metadata(str) + error_code(2)]]
func buildOffsetFetchResponse(body []byte) []byte {
	type partReq struct {
		partition int32
	}
	type topicReq struct {
		name       string
		partitions []partReq
	}

	// Parse request: group_id(str) + topics[name(str) + partitions[partition(4)]]
	off := 0
	// skip group_id
	if off+2 <= len(body) {
		gLen := int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2
		if gLen > 0 {
			off += gLen
		}
	}

	var topics []topicReq
	if off+4 <= len(body) {
		tCount := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		for i := 0; i < tCount && off+2 <= len(body); i++ {
			tLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			name := ""
			if tLen > 0 && off+tLen <= len(body) {
				name = string(body[off : off+tLen])
				off += tLen
			}
			tr := topicReq{name: name}
			if off+4 <= len(body) {
				pCount := int(binary.BigEndian.Uint32(body[off : off+4]))
				off += 4
				for j := 0; j < pCount && off+4 <= len(body); j++ {
					tr.partitions = append(tr.partitions, partReq{
						partition: int32(binary.BigEndian.Uint32(body[off : off+4])),
					})
					off += 4
				}
			}
			topics = append(topics, tr)
		}
	}

	buf := make([]byte, 0, 256)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(topics)))
	for _, t := range topics {
		buf = appendString(buf, t.name)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(t.partitions)))
		for _, p := range t.partitions {
			buf = binary.BigEndian.AppendUint32(buf, uint32(p.partition))
			buf = binary.BigEndian.AppendUint64(buf, 0xFFFFFFFFFFFFFFFF) // offset -1 (no committed)
			buf = appendString(buf, "")                                  // metadata
			buf = binary.BigEndian.AppendUint16(buf, 0)                  // no error
		}
	}
	return buf
}

// parseOffsetFetchTopics extracts topic names from an OffsetFetch request for logging.
func parseOffsetFetchTopics(body []byte) []string {
	off := 0
	if off+2 <= len(body) {
		gLen := int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2 + gLen
	}
	var topics []string
	if off+4 <= len(body) {
		tCount := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		for i := 0; i < tCount && off+2 <= len(body); i++ {
			tLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			if tLen > 0 && off+tLen <= len(body) {
				topics = append(topics, string(body[off:off+tLen]))
				off += tLen
			}
			// skip partitions
			if off+4 <= len(body) {
				pCount := int(binary.BigEndian.Uint32(body[off : off+4]))
				off += 4 + pCount*4
			}
		}
	}
	return topics
}

// buildOffsetCommitResponse accepts all commits and returns success.
// v0-v2: topics[name + partitions[partition(4) + error_code(2)]]
func buildOffsetCommitResponse(body []byte) []byte {
	type partReq struct {
		partition int32
	}
	type topicReq struct {
		name       string
		partitions []partReq
	}

	// Parse request: group_id(str) + [generation_id(4) + member_id(str) in v1+] + topics[...]
	// For simplicity, skip to topics by scanning for the array structure
	off := 0
	// skip group_id
	if off+2 <= len(body) {
		gLen := int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2
		if gLen > 0 {
			off += gLen
		}
	}
	// v1+: generation_id(4) + member_id(str) [+ retention_time(8) in v2+]
	// We detect v1+ by checking if there's enough data for generation_id
	// Since we handle v0-v2, try to find the topics array
	// Heuristic: skip 4 bytes (generation_id), then a string (member_id), then optionally 8 bytes (retention)
	// Try each offset to find a valid topic array
	saved := off
	// Try v1+ layout: generation(4) + member_id(str) + topics
	if off+4 <= len(body) {
		off += 4 // generation_id
		if off+2 <= len(body) {
			mLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			if mLen > 0 {
				off += mLen
			}
		}
	}

	var topics []topicReq
	if off+4 <= len(body) {
		tCount := int(binary.BigEndian.Uint32(body[off : off+4]))
		// Sanity check: if tCount is unreasonable, try v0 layout
		if tCount <= 0 || tCount > 100 {
			off = saved
		} else {
			off += 4
		}
	} else {
		off = saved
	}

	if len(topics) == 0 && off+4 <= len(body) {
		tCount := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		for i := 0; i < tCount && tCount <= 100 && off+2 <= len(body); i++ {
			tLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			name := ""
			if tLen > 0 && off+tLen <= len(body) {
				name = string(body[off : off+tLen])
				off += tLen
			}
			tr := topicReq{name: name}
			if off+4 <= len(body) {
				pCount := int(binary.BigEndian.Uint32(body[off : off+4]))
				off += 4
				for j := 0; j < pCount && off+4 <= len(body); j++ {
					tr.partitions = append(tr.partitions, partReq{
						partition: int32(binary.BigEndian.Uint32(body[off : off+4])),
					})
					off += 4
					off += 8 // skip offset(8)
					if off+2 <= len(body) {
						mLen := int(binary.BigEndian.Uint16(body[off : off+2]))
						off += 2
						if mLen > 0 {
							off += mLen // skip metadata
						}
					}
				}
			}
			topics = append(topics, tr)
		}
	}

	buf := make([]byte, 0, 128)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(topics)))
	for _, t := range topics {
		buf = appendString(buf, t.name)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(t.partitions)))
		for _, p := range t.partitions {
			buf = binary.BigEndian.AppendUint32(buf, uint32(p.partition))
			buf = binary.BigEndian.AppendUint16(buf, 0) // no error
		}
	}
	return buf
}

// fakeGroups are consumer groups returned by ListGroups.
var fakeGroups = []struct {
	groupID      string
	protocolType string
}{
	{"billing-processor", "consumer"},
	{"session-tracker", "consumer"},
	{"audit-writer", "consumer"},
}

// buildListGroupsResponse returns a list of fake consumer groups.
func buildListGroupsResponse() []byte {
	buf := make([]byte, 0, 128)
	// error_code: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// groups array
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(fakeGroups)))
	for _, g := range fakeGroups {
		buf = appendString(buf, g.groupID)
		buf = appendString(buf, g.protocolType)
	}
	return buf
}

// parseDescribeGroupsRequest extracts group IDs from the request.
func parseDescribeGroupsRequest(body []byte) []string {
	off := 0
	var groups []string
	if off+4 <= len(body) {
		count := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		for i := 0; i < count && off+2 <= len(body); i++ {
			gLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			if gLen > 0 && off+gLen <= len(body) {
				groups = append(groups, string(body[off:off+gLen]))
				off += gLen
			}
		}
	}
	return groups
}

// buildDescribeGroupsResponse returns details for requested groups.
func buildDescribeGroupsResponse(groupIDs []string) []byte {
	buf := make([]byte, 0, 512)
	// groups array
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(groupIDs)))
	for _, gid := range groupIDs {
		// error_code: 0
		buf = binary.BigEndian.AppendUint16(buf, 0)
		// group_id
		buf = appendString(buf, gid)
		// state
		buf = appendString(buf, "Stable")
		// protocol_type
		buf = appendString(buf, "consumer")
		// protocol (assigned)
		buf = appendString(buf, "range")
		// members array — 1 fake member per group
		buf = binary.BigEndian.AppendUint32(buf, 1)
		// member_id
		fakeMember := fmt.Sprintf("%s-member-0", gid)
		buf = appendString(buf, fakeMember)
		// client_id
		buf = appendString(buf, "consumer-client-1")
		// client_host
		buf = appendString(buf, "/10.0.1.100")
		// member_metadata
		meta := buildConsumerSubscription()
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(meta)))
		buf = append(buf, meta...)
		// member_assignment
		assignment := buildConsumerAssignment()
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(assignment)))
		buf = append(buf, assignment...)
	}
	return buf
}
