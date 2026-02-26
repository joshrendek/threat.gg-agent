package kafka

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestKcatServer starts a Kafka protocol server for manual kcat testing.
// Run with: go test ./kafka/ -run TestKcatServer -v -timeout 120s
// Then in another terminal:
//
//	kcat -L -b 127.0.0.1:19092                                    # list topics
//	kcat -C -b 127.0.0.1:19092 -t api-keys -o beginning -c 10    # consume messages
//	echo '{"test":true}' | kcat -P -b 127.0.0.1:19092 -t api-keys # produce
func TestKcatServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping manual kcat test in short mode")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:19092")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	t.Logf("Kafka honeypot test server listening on 127.0.0.1:19092")
	t.Logf("Test commands:")
	t.Logf("  kcat -L -b 127.0.0.1:19092")
	t.Logf("  kcat -C -b 127.0.0.1:19092 -t api-keys -o beginning -c 10")
	t.Logf("  echo '{\"test\":true}' | kcat -P -b 127.0.0.1:19092 -t api-keys")

	done := make(chan struct{})
	go func() {
		time.Sleep(60 * time.Second)
		close(done)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			sess := &session{guid: "kcat-test"}
			c.SetDeadline(time.Now().Add(30 * time.Second))
			for i := 0; i < 500; i++ {
				hdr, body, err := readRequest(c)
				if err != nil {
					if err != io.EOF {
						t.Logf("read error: %v", err)
					}
					return
				}
				t.Logf("Request: ApiKey=%d(%s) Version=%d CorrID=%d Client=%q",
					hdr.ApiKey, apiKeyName(hdr.ApiKey), hdr.ApiVersion, hdr.CorrelationID, hdr.ClientID)

				var resp []byte

				switch hdr.ApiKey {
				case apiApiVersions:
					if hdr.ApiVersion >= 3 {
						resp = buildApiVersionsV3Response()
					} else {
						resp = buildApiVersionsResponse()
					}
				case apiMetadata:
					resp = buildMetadataResponse()
				case apiSaslHandshake:
					resp = buildSaslHandshakeResponse()
				case apiSaslAuthenticate:
					parseSaslPlain(body)
					resp = buildSaslAuthenticateResponse()
				case apiFindCoordinator:
					resp = buildFindCoordinatorResponse()
				case apiProduce:
					resp = buildProduceResponse(body)
				case apiFetch:
					resp = buildFetchResponse(sess, body)
				case apiListOffsets:
					resp = buildListOffsetsResponse(body, hdr.ApiVersion)
				case apiJoinGroup:
					groupID, _, memberID, _, _ := parseJoinGroupRequest(body, hdr.ApiVersion)
					if memberID == "" {
						memberID = "kcat-test-member-0"
					}
					sess.groupID = groupID
					sess.memberID = memberID
					sess.generation++
					resp = buildJoinGroupResponse(sess, groupID, memberID, sess.generation)
				case apiSyncGroup:
					resp = buildSyncGroupResponse()
				case apiHeartbeat:
					resp = buildHeartbeatResponse()
				case apiLeaveGroup:
					resp = buildLeaveGroupResponse()
				case apiOffsetFetch:
					resp = buildOffsetFetchResponse(body)
				case apiOffsetCommit:
					resp = buildOffsetCommitResponse(body)
				case apiListGroups:
					resp = buildListGroupsResponse()
				case apiDescribeGroups:
					groupIDs := parseDescribeGroupsRequest(body)
					resp = buildDescribeGroupsResponse(groupIDs)
				default:
					resp = []byte{0, 35}
				}

				if err := writeResponse(c, hdr.CorrelationID, resp); err != nil {
					t.Logf("write error: %v", err)
					return
				}
			}
		}(conn)
	}
}
