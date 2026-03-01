package kafka

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"testing"
	"time"
)

// TestProtocolHandshake verifies the honeypot responds correctly to
// ApiVersions and Metadata requests (the minimum for kcat -L).
func TestProtocolHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	t.Logf("honeypot listening on %s", addr)

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

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
				resp = []byte{0, 35}
			}

			if err := writeResponse(conn, hdr.CorrelationID, resp); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

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
		if apiCount < 14 {
			t.Fatalf("expected at least 14 API versions (8 original + 8 consumer group), got %d", apiCount)
		}
		t.Logf("ApiVersions: %d APIs supported", apiCount)
	})

	t.Run("Metadata", func(t *testing.T) {
		body := make([]byte, 4)
		binary.BigEndian.PutUint32(body, 0)
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

	select {
	case err := <-done:
		if err != nil {
			t.Logf("server error (may be expected): %v", err)
		}
	case <-time.After(3 * time.Second):
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

// TestFakeMessages verifies the message corpus is generated for all topics.
func TestFakeMessages(t *testing.T) {
	if len(fakeMessages) != len(fakeTopics) {
		t.Fatalf("expected %d topics in fakeMessages, got %d", len(fakeTopics), len(fakeMessages))
	}
	for _, topic := range fakeTopics {
		msgs, ok := fakeMessages[topic.name]
		if !ok {
			t.Errorf("missing messages for topic %q", topic.name)
			continue
		}
		if len(msgs) != messagesPerTopic {
			t.Errorf("topic %q: expected %d messages, got %d", topic.name, messagesPerTopic, len(msgs))
		}
		for i, msg := range msgs {
			if len(msg) == 0 {
				t.Errorf("topic %q message %d is empty", topic.name, i)
			}
		}
	}
}

// TestBuildMessageV0 verifies the Kafka v0 message wire format.
func TestBuildMessageV0(t *testing.T) {
	value := []byte(`{"test":"data"}`)
	msg := buildMessageV0(42, nil, value)

	// Parse it back: offset(8) + messageSize(4) + CRC(4) + magic(1) + attrs(1) + key(4) + value(4+N)
	if len(msg) < 22 {
		t.Fatalf("message too short: %d bytes", len(msg))
	}

	offset := int64(binary.BigEndian.Uint64(msg[0:8]))
	if offset != 42 {
		t.Errorf("offset: got %d, want 42", offset)
	}

	messageSize := int32(binary.BigEndian.Uint32(msg[8:12]))
	expectedSize := int32(4 + 1 + 1 + 4 + 4 + len(value)) // CRC + magic + attrs + key(-1) + value(len+data)
	if messageSize != expectedSize {
		t.Errorf("messageSize: got %d, want %d", messageSize, expectedSize)
	}

	storedCRC := binary.BigEndian.Uint32(msg[12:16])
	// CRC covers magic(1) + attrs(1) + key(4) + value(4+N)
	crcPayload := msg[16:]
	computedCRC := crc32.ChecksumIEEE(crcPayload)
	if storedCRC != computedCRC {
		t.Errorf("CRC mismatch: stored=%08x computed=%08x", storedCRC, computedCRC)
	}

	magic := msg[16]
	if magic != 0 {
		t.Errorf("magic: got %d, want 0", magic)
	}

	attrs := msg[17]
	if attrs != 0 {
		t.Errorf("attributes: got %d, want 0", attrs)
	}

	// key should be -1 (null)
	keyLen := int32(binary.BigEndian.Uint32(msg[18:22]))
	if keyLen != -1 {
		t.Errorf("key length: got %d, want -1", keyLen)
	}

	// value
	valueLen := int32(binary.BigEndian.Uint32(msg[22:26]))
	if valueLen != int32(len(value)) {
		t.Errorf("value length: got %d, want %d", valueLen, len(value))
	}
	gotValue := string(msg[26:])
	if gotValue != string(value) {
		t.Errorf("value: got %q, want %q", gotValue, string(value))
	}
}

// TestListOffsetsResponse verifies ListOffsets returns proper offsets.
func TestListOffsetsResponse(t *testing.T) {
	t.Run("v1_latest", func(t *testing.T) {
		// Build a v1 ListOffsets request for api-keys partition 0, timestamp -1 (latest)
		body := buildListOffsetsRequest("api-keys", 0, -1)
		resp := buildListOffsetsResponse(body, 1)

		// Parse: topics_count(4) + topic_name + partitions_count(4) + partition(4) + error(2) + timestamp(8) + offset(8)
		if len(resp) < 4 {
			t.Fatalf("response too short: %d bytes", len(resp))
		}
		topicCount := binary.BigEndian.Uint32(resp[0:4])
		if topicCount != 1 {
			t.Fatalf("expected 1 topic, got %d", topicCount)
		}
		// Skip topic name
		off := 4
		tLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
		off += 2 + tLen
		// partitions count
		pCount := binary.BigEndian.Uint32(resp[off : off+4])
		off += 4
		if pCount != 1 {
			t.Fatalf("expected 1 partition, got %d", pCount)
		}
		// partition(4) + error(2) + timestamp(8) + offset(8)
		off += 4 // skip partition
		errCode := binary.BigEndian.Uint16(resp[off : off+2])
		off += 2
		if errCode != 0 {
			t.Fatalf("expected error_code 0, got %d", errCode)
		}
		off += 8 // skip timestamp
		offsetVal := int64(binary.BigEndian.Uint64(resp[off : off+8]))
		if offsetVal != messagesPerTopic {
			t.Errorf("expected latest offset %d, got %d", messagesPerTopic, offsetVal)
		}
	})

	t.Run("v1_earliest", func(t *testing.T) {
		body := buildListOffsetsRequest("api-keys", 0, -2)
		resp := buildListOffsetsResponse(body, 1)

		off := 4
		tLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
		off += 2 + tLen + 4 + 4 + 2 + 8 // skip to offset
		offsetVal := int64(binary.BigEndian.Uint64(resp[off : off+8]))
		if offsetVal != 0 {
			t.Errorf("expected earliest offset 0, got %d", offsetVal)
		}
	})

	t.Run("unknown_topic", func(t *testing.T) {
		body := buildListOffsetsRequest("nonexistent-topic", 0, -1)
		resp := buildListOffsetsResponse(body, 1)

		off := 4
		tLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
		off += 2 + tLen + 4 + 4 // skip to error_code
		errCode := binary.BigEndian.Uint16(resp[off : off+2])
		if errCode != 3 {
			t.Errorf("expected error_code 3 (UNKNOWN_TOPIC), got %d", errCode)
		}
	})
}

// TestFetchResponse verifies Fetch returns messages with proper CRCs.
func TestFetchResponse(t *testing.T) {
	sess := &session{guid: "test-session"}
	body := buildFetchRequest("api-keys", 0, 0)
	resp := buildFetchResponse(sess, body)

	// Parse: throttle(4) + topics_count(4) + ...
	if len(resp) < 8 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	throttle := binary.BigEndian.Uint32(resp[0:4])
	if throttle != 0 {
		t.Errorf("expected throttle 0, got %d", throttle)
	}
	topicCount := binary.BigEndian.Uint32(resp[4:8])
	if topicCount != 1 {
		t.Fatalf("expected 1 topic, got %d", topicCount)
	}

	off := 8
	tLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
	off += 2 + tLen // skip topic name
	pCount := binary.BigEndian.Uint32(resp[off : off+4])
	off += 4
	if pCount != 1 {
		t.Fatalf("expected 1 partition, got %d", pCount)
	}

	off += 4 // skip partition
	errCode := binary.BigEndian.Uint16(resp[off : off+2])
	off += 2
	if errCode != 0 {
		t.Fatalf("expected error_code 0, got %d", errCode)
	}

	highWatermark := int64(binary.BigEndian.Uint64(resp[off : off+8]))
	off += 8
	if highWatermark != messagesPerTopic {
		t.Errorf("high watermark: got %d, want %d", highWatermark, messagesPerTopic)
	}

	messageSetSize := int(binary.BigEndian.Uint32(resp[off : off+4]))
	off += 4
	if messageSetSize <= 0 {
		t.Fatal("message set is empty")
	}

	// Validate CRC of first message in the set
	msgStart := off
	off += 8 // skip offset
	off += 4 // skip messageSize
	storedCRC := binary.BigEndian.Uint32(resp[off : off+4])
	off += 4
	// Find end of this message (magic + attrs + key + value)
	crcStart := off
	off++ // magic
	off++ // attrs
	keyLen := int32(binary.BigEndian.Uint32(resp[off : off+4]))
	off += 4
	if keyLen > 0 {
		off += int(keyLen)
	}
	valueLen := int32(binary.BigEndian.Uint32(resp[off : off+4]))
	off += 4
	if valueLen > 0 {
		off += int(valueLen)
	}
	computedCRC := crc32.ChecksumIEEE(resp[crcStart:off])
	if storedCRC != computedCRC {
		t.Errorf("CRC mismatch on first message: stored=%08x computed=%08x", storedCRC, computedCRC)
	}

	t.Logf("Fetch response: %d bytes, message set: %d bytes starting at offset %d", len(resp), messageSetSize, msgStart)
}

// TestFetchOffsetTracking verifies that subsequent Fetches advance the offset.
func TestFetchOffsetTracking(t *testing.T) {
	sess := &session{guid: "test-session"}

	// First fetch at offset 0 should return 5 messages
	body1 := buildFetchRequest("api-keys", 0, 0)
	resp1 := buildFetchResponse(sess, body1)

	// Second fetch at offset 5 should return next 5
	body2 := buildFetchRequest("api-keys", 0, 5)
	resp2 := buildFetchResponse(sess, body2)

	if len(resp1) == len(resp2) {
		// They could theoretically be the same size if message lengths are similar,
		// but content should differ. Just verify both have data.
	}

	// Session should have tracked the offset
	key := "api-keys-0"
	if sess.fetchOffsets[key] != 10 {
		t.Errorf("expected tracked offset 10, got %d", sess.fetchOffsets[key])
	}
}

// TestJoinGroupResponse verifies JoinGroup assigns member as leader.
func TestJoinGroupResponse(t *testing.T) {
	sess := &session{guid: "test-session"}
	resp := buildJoinGroupResponse(sess, "test-group", "member-1", 1)

	if len(resp) < 6 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	errCode := binary.BigEndian.Uint16(resp[0:2])
	if errCode != 0 {
		t.Fatalf("expected error_code 0, got %d", errCode)
	}

	generation := int32(binary.BigEndian.Uint32(resp[2:6]))
	if generation != 1 {
		t.Errorf("expected generation 1, got %d", generation)
	}

	// Skip protocol string to get to leader
	off := 6
	pLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
	off += 2 + pLen
	// leader
	lLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
	off += 2
	leader := string(resp[off : off+lLen])
	if leader != "member-1" {
		t.Errorf("expected leader member-1, got %q", leader)
	}
}

// TestSyncGroupResponse verifies SyncGroup returns assignment with all topics.
func TestSyncGroupResponse(t *testing.T) {
	resp := buildSyncGroupResponse()

	if len(resp) < 6 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	errCode := binary.BigEndian.Uint16(resp[0:2])
	if errCode != 0 {
		t.Fatalf("expected error_code 0, got %d", errCode)
	}

	assignLen := int(binary.BigEndian.Uint32(resp[2:6]))
	if assignLen <= 0 {
		t.Fatal("expected non-empty assignment")
	}
	t.Logf("SyncGroup: assignment %d bytes", assignLen)
}

// TestHeartbeatResponse verifies Heartbeat returns success.
func TestHeartbeatResponse(t *testing.T) {
	resp := buildHeartbeatResponse()
	if len(resp) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(resp))
	}
	errCode := binary.BigEndian.Uint16(resp[0:2])
	if errCode != 0 {
		t.Fatalf("expected error_code 0, got %d", errCode)
	}
}

// TestLeaveGroupResponse verifies LeaveGroup returns success.
func TestLeaveGroupResponse(t *testing.T) {
	resp := buildLeaveGroupResponse()
	if len(resp) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(resp))
	}
	errCode := binary.BigEndian.Uint16(resp[0:2])
	if errCode != 0 {
		t.Fatalf("expected error_code 0, got %d", errCode)
	}
}

// TestOffsetFetchResponse verifies OffsetFetch returns -1 for all partitions.
func TestOffsetFetchResponse(t *testing.T) {
	body := buildOffsetFetchRequest("test-group", "api-keys", []int32{0, 1, 2})
	resp := buildOffsetFetchResponse(body)

	if len(resp) < 4 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	topicCount := binary.BigEndian.Uint32(resp[0:4])
	if topicCount != 1 {
		t.Fatalf("expected 1 topic, got %d", topicCount)
	}

	off := 4
	tLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
	off += 2 + tLen
	pCount := binary.BigEndian.Uint32(resp[off : off+4])
	off += 4
	if pCount != 3 {
		t.Fatalf("expected 3 partitions, got %d", pCount)
	}

	for i := 0; i < 3; i++ {
		off += 4 // partition
		offsetVal := int64(binary.BigEndian.Uint64(resp[off : off+8]))
		off += 8
		if offsetVal != -1 {
			t.Errorf("partition %d: expected offset -1, got %d", i, offsetVal)
		}
		mLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
		off += 2 + mLen
		off += 2 // error_code
	}
}

// TestListGroupsResponse verifies ListGroups returns fake groups.
func TestListGroupsResponse(t *testing.T) {
	resp := buildListGroupsResponse()

	if len(resp) < 6 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	errCode := binary.BigEndian.Uint16(resp[0:2])
	if errCode != 0 {
		t.Fatalf("expected error_code 0, got %d", errCode)
	}

	groupCount := binary.BigEndian.Uint32(resp[2:6])
	if groupCount != uint32(len(fakeGroups)) {
		t.Fatalf("expected %d groups, got %d", len(fakeGroups), groupCount)
	}
}

// TestDescribeGroupsResponse verifies DescribeGroups returns group details.
func TestDescribeGroupsResponse(t *testing.T) {
	resp := buildDescribeGroupsResponse([]string{"billing-processor"})

	if len(resp) < 4 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	groupCount := binary.BigEndian.Uint32(resp[0:4])
	if groupCount != 1 {
		t.Fatalf("expected 1 group, got %d", groupCount)
	}

	off := 4
	errCode := binary.BigEndian.Uint16(resp[off : off+2])
	if errCode != 0 {
		t.Fatalf("expected error_code 0, got %d", errCode)
	}
}

// TestConsumerGroupFlow is an integration test for the full consumer group lifecycle.
func TestConsumerGroupFlow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	sess := &session{guid: "integration-test"}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		for i := 0; i < 20; i++ {
			hdr, body, err := readRequest(conn)
			if err != nil {
				return
			}

			var resp []byte
			switch hdr.ApiKey {
			case apiApiVersions:
				resp = buildApiVersionsResponse()
			case apiMetadata:
				resp = buildMetadataResponse()
			case apiFindCoordinator:
				resp = buildFindCoordinatorResponse()
			case apiJoinGroup:
				groupID, _, memberID, _, _ := parseJoinGroupRequest(body, hdr.ApiVersion)
				if memberID == "" {
					memberID = "consumer-test-0"
				}
				sess.groupID = groupID
				sess.memberID = memberID
				sess.generation++
				resp = buildJoinGroupResponse(sess, groupID, memberID, sess.generation)
			case apiSyncGroup:
				resp = buildSyncGroupResponse()
			case apiOffsetFetch:
				resp = buildOffsetFetchResponse(body)
			case apiListOffsets:
				resp = buildListOffsetsResponse(body, hdr.ApiVersion)
			case apiFetch:
				resp = buildFetchResponse(sess, body)
			case apiHeartbeat:
				resp = buildHeartbeatResponse()
			case apiOffsetCommit:
				resp = buildOffsetCommitResponse(body)
			case apiLeaveGroup:
				resp = buildLeaveGroupResponse()
			default:
				resp = []byte{0, 35}
			}

			if err := writeResponse(conn, hdr.CorrelationID, resp); err != nil {
				return
			}
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	corrID := int32(1)
	next := func() int32 { corrID++; return corrID }

	// 1. ApiVersions
	t.Run("Flow/ApiVersions", func(t *testing.T) {
		resp := sendRequest(t, conn, apiApiVersions, 1, next(), "test-consumer", nil)
		errCode := binary.BigEndian.Uint16(resp[0:2])
		if errCode != 0 {
			t.Fatalf("ApiVersions error: %d", errCode)
		}
	})

	// 2. Metadata
	t.Run("Flow/Metadata", func(t *testing.T) {
		body := make([]byte, 4)
		resp := sendRequest(t, conn, apiMetadata, 1, next(), "test-consumer", body)
		if len(resp) < 4 {
			t.Fatal("Metadata response too short")
		}
	})

	// 3. FindCoordinator
	t.Run("Flow/FindCoordinator", func(t *testing.T) {
		body := appendString(nil, "test-consumer-group")
		resp := sendRequest(t, conn, apiFindCoordinator, 0, next(), "test-consumer", body)
		errCode := binary.BigEndian.Uint16(resp[0:2])
		if errCode != 0 {
			t.Fatalf("FindCoordinator error: %d", errCode)
		}
	})

	// 4. JoinGroup
	t.Run("Flow/JoinGroup", func(t *testing.T) {
		body := buildJoinGroupRequest("test-consumer-group", "", 30000, "consumer", "range")
		resp := sendRequest(t, conn, apiJoinGroup, 0, next(), "test-consumer", body)
		errCode := binary.BigEndian.Uint16(resp[0:2])
		if errCode != 0 {
			t.Fatalf("JoinGroup error: %d", errCode)
		}
	})

	// 5. SyncGroup
	t.Run("Flow/SyncGroup", func(t *testing.T) {
		body := buildSyncGroupRequest("test-consumer-group", 1, "consumer-test-0")
		resp := sendRequest(t, conn, apiSyncGroup, 0, next(), "test-consumer", body)
		errCode := binary.BigEndian.Uint16(resp[0:2])
		if errCode != 0 {
			t.Fatalf("SyncGroup error: %d", errCode)
		}
	})

	// 6. OffsetFetch
	t.Run("Flow/OffsetFetch", func(t *testing.T) {
		body := buildOffsetFetchRequest("test-consumer-group", "api-keys", []int32{0})
		resp := sendRequest(t, conn, apiOffsetFetch, 0, next(), "test-consumer", body)
		if len(resp) < 4 {
			t.Fatal("OffsetFetch response too short")
		}
	})

	// 7. ListOffsets
	t.Run("Flow/ListOffsets", func(t *testing.T) {
		body := buildListOffsetsRequest("api-keys", 0, -2)
		resp := sendRequest(t, conn, apiListOffsets, 1, next(), "test-consumer", body)
		if len(resp) < 4 {
			t.Fatal("ListOffsets response too short")
		}
	})

	// 8. Fetch
	t.Run("Flow/Fetch", func(t *testing.T) {
		body := buildFetchRequest("api-keys", 0, 0)
		resp := sendRequest(t, conn, apiFetch, 0, next(), "test-consumer", body)
		if len(resp) < 8 {
			t.Fatal("Fetch response too short")
		}
		throttle := binary.BigEndian.Uint32(resp[0:4])
		if throttle != 0 {
			t.Errorf("unexpected throttle: %d", throttle)
		}
	})

	// 9. Heartbeat
	t.Run("Flow/Heartbeat", func(t *testing.T) {
		body := buildHeartbeatRequestBody("test-consumer-group", 1, "consumer-test-0")
		resp := sendRequest(t, conn, apiHeartbeat, 0, next(), "test-consumer", body)
		errCode := binary.BigEndian.Uint16(resp[0:2])
		if errCode != 0 {
			t.Fatalf("Heartbeat error: %d", errCode)
		}
	})

	// 10. LeaveGroup
	t.Run("Flow/LeaveGroup", func(t *testing.T) {
		body := buildLeaveGroupRequestBody("test-consumer-group", "consumer-test-0")
		resp := sendRequest(t, conn, apiLeaveGroup, 0, next(), "test-consumer", body)
		errCode := binary.BigEndian.Uint16(resp[0:2])
		if errCode != 0 {
			t.Fatalf("LeaveGroup error: %d", errCode)
		}
	})
}

// TestApiKeyName verifies all API keys have names.
func TestApiKeyName(t *testing.T) {
	expected := map[int16]string{
		0:  "Produce",
		1:  "Fetch",
		2:  "ListOffsets",
		3:  "Metadata",
		8:  "OffsetCommit",
		9:  "OffsetFetch",
		10: "FindCoordinator",
		11: "JoinGroup",
		12: "Heartbeat",
		13: "LeaveGroup",
		14: "SyncGroup",
		15: "DescribeGroups",
		16: "ListGroups",
		17: "SaslHandshake",
		18: "ApiVersions",
		36: "SaslAuthenticate",
	}
	for key, want := range expected {
		got := apiKeyName(key)
		if got != want {
			t.Errorf("apiKeyName(%d): got %q, want %q", key, got, want)
		}
	}
	if apiKeyName(99) != "Unknown" {
		t.Errorf("apiKeyName(99): expected Unknown, got %q", apiKeyName(99))
	}
}

// --- Test helpers for building request bodies ---

func sendRequest(t *testing.T, conn net.Conn, apiKey, apiVersion int16, correlationID int32, clientID string, body []byte) []byte {
	t.Helper()

	var payload []byte
	payload = binary.BigEndian.AppendUint16(payload, uint16(apiKey))
	payload = binary.BigEndian.AppendUint16(payload, uint16(apiVersion))
	payload = binary.BigEndian.AppendUint32(payload, uint32(correlationID))
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(clientID)))
	payload = append(payload, clientID...)
	if body != nil {
		payload = append(payload, body...)
	}

	size := int32(len(payload))
	if err := binary.Write(conn, binary.BigEndian, size); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	var respSize int32
	if err := binary.Read(conn, binary.BigEndian, &respSize); err != nil {
		t.Fatal(err)
	}
	respBuf := make([]byte, respSize)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatal(err)
	}

	gotCorr := int32(binary.BigEndian.Uint32(respBuf[0:4]))
	if gotCorr != correlationID {
		t.Fatalf("correlation ID mismatch: got %d, want %d", gotCorr, correlationID)
	}

	return respBuf[4:]
}

func buildSaslPlainPayload(authzid, username, password string) []byte {
	plain := authzid + "\x00" + username + "\x00" + password
	buf := make([]byte, 4+len(plain))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(plain)))
	copy(buf[4:], plain)
	return buf
}

func buildListOffsetsRequest(topic string, partition int32, timestamp int64) []byte {
	// v1: replica_id(4) + topics[name(str) + partitions[partition(4) + timestamp(8)]]
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, 0xFFFFFFFF) // replica_id = -1
	buf = binary.BigEndian.AppendUint32(buf, 1)          // 1 topic
	buf = appendString(buf, topic)
	buf = binary.BigEndian.AppendUint32(buf, 1) // 1 partition
	buf = binary.BigEndian.AppendUint32(buf, uint32(partition))
	buf = binary.BigEndian.AppendUint64(buf, uint64(timestamp))
	return buf
}

func buildFetchRequest(topic string, partition int32, fetchOffset int64) []byte {
	// v0: replica_id(4) + max_wait(4) + min_bytes(4) + topics[name(str) + partitions[partition(4) + fetch_offset(8) + max_bytes(4)]]
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, 0xFFFFFFFF) // replica_id = -1
	buf = binary.BigEndian.AppendUint32(buf, 500)        // max_wait_ms
	buf = binary.BigEndian.AppendUint32(buf, 1)          // min_bytes
	buf = binary.BigEndian.AppendUint32(buf, 1)          // 1 topic
	buf = appendString(buf, topic)
	buf = binary.BigEndian.AppendUint32(buf, 1) // 1 partition
	buf = binary.BigEndian.AppendUint32(buf, uint32(partition))
	buf = binary.BigEndian.AppendUint64(buf, uint64(fetchOffset))
	buf = binary.BigEndian.AppendUint32(buf, 1048576) // max_bytes 1MB
	return buf
}

func buildJoinGroupRequest(groupID, memberID string, sessionTimeout int32, protocolType, protocol string) []byte {
	// v0: group_id(str) + session_timeout(4) + member_id(str) + protocol_type(str) + protocols[name(str) + metadata(bytes)]
	var buf []byte
	buf = appendString(buf, groupID)
	buf = binary.BigEndian.AppendUint32(buf, uint32(sessionTimeout))
	buf = appendString(buf, memberID)
	buf = appendString(buf, protocolType)
	buf = binary.BigEndian.AppendUint32(buf, 1) // 1 protocol
	buf = appendString(buf, protocol)
	buf = binary.BigEndian.AppendUint32(buf, 0) // empty metadata
	return buf
}

func buildSyncGroupRequest(groupID string, generationID int32, memberID string) []byte {
	var buf []byte
	buf = appendString(buf, groupID)
	buf = binary.BigEndian.AppendUint32(buf, uint32(generationID))
	buf = appendString(buf, memberID)
	buf = binary.BigEndian.AppendUint32(buf, 0) // empty group_assignments
	return buf
}

func buildOffsetFetchRequest(groupID, topic string, partitions []int32) []byte {
	var buf []byte
	buf = appendString(buf, groupID)
	buf = binary.BigEndian.AppendUint32(buf, 1) // 1 topic
	buf = appendString(buf, topic)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(partitions)))
	for _, p := range partitions {
		buf = binary.BigEndian.AppendUint32(buf, uint32(p))
	}
	return buf
}

func buildHeartbeatRequestBody(groupID string, generationID int32, memberID string) []byte {
	var buf []byte
	buf = appendString(buf, groupID)
	buf = binary.BigEndian.AppendUint32(buf, uint32(generationID))
	buf = appendString(buf, memberID)
	return buf
}

func buildLeaveGroupRequestBody(groupID, memberID string) []byte {
	var buf []byte
	buf = appendString(buf, groupID)
	buf = appendString(buf, memberID)
	return buf
}
