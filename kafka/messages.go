package kafka

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// messagesPerTopic is the number of fake messages generated per topic.
const messagesPerTopic = 50

// fakeMessages maps topic name to pre-built JSON payloads.
var fakeMessages map[string][][]byte

func init() {
	fakeMessages = make(map[string][][]byte, len(fakeTopics))
	for _, t := range fakeTopics {
		msgs := make([][]byte, messagesPerTopic)
		for i := 0; i < messagesPerTopic; i++ {
			msgs[i] = generateMessage(t.name, i)
		}
		fakeMessages[t.name] = msgs
	}
}

func generateMessage(topic string, idx int) []byte {
	var s string
	switch topic {
	case "internal-credentials":
		s = fmt.Sprintf(`{"service":"svc-%d-api","username":"svc-user-%d","password":"%s","env":"production","rotated_at":"2026-02-%02dT%02d:30:00Z"}`,
			idx%8, idx, fakeB64Passwords[idx%len(fakeB64Passwords)], (idx%28)+1, idx%24)
	case "user-sessions":
		s = fmt.Sprintf(`{"user_id":"usr_%06x","email":"user%d@example.com","session_token":"eyJhbGciOiJIUzI1NiJ9.%06x.fake","ip":"10.0.%d.%d","created_at":"2026-02-%02dT%02d:%02d:00Z"}`,
			idx*7919, idx, idx*13, idx%256, (idx*3)%256, (idx%28)+1, idx%24, idx%60)
	case "payment-events":
		s = fmt.Sprintf(`{"event":"payment.completed","amount":%d,"currency":"USD","card_last4":"%04d","customer_id":"cust_%05x","merchant":"merchant-%d"}`,
			(idx+1)*1499, (idx*1111)%10000, idx*3571, idx%20)
	case "api-keys":
		s = fmt.Sprintf(`{"key_id":"ak_live_%06x","key":"sk_live_%012x","permissions":["read","write"%s],"created_at":"2026-01-%02dT12:00:00Z"}`,
			idx*2749, idx*9973, adminPerm(idx), (idx%28)+1)
	case "admin-notifications":
		s = fmt.Sprintf(`{"type":"%s","severity":"%s","message":"%s","source":"10.0.%d.%d","timestamp":"2026-02-%02dT%02d:%02d:00Z"}`,
			alertTypes[idx%len(alertTypes)], severities[idx%len(severities)], alertMessages[idx%len(alertMessages)],
			idx%256, (idx*7)%256, (idx%28)+1, idx%24, idx%60)
	case "pii-exports":
		s = fmt.Sprintf(`{"export_id":"exp_%05x","record_count":%d,"tables":["%s"],"requested_by":"admin-%d@corp.internal","format":"csv","status":"completed"}`,
			idx*4157, (idx+1)*1542, piiTables[idx%len(piiTables)], idx%5)
	case "audit-log":
		s = fmt.Sprintf(`{"actor":"admin%d@corp.internal","action":"%s","target":"%s:%d","changes":%s,"ip":"10.0.1.%d","timestamp":"2026-02-%02dT%02d:%02d:00Z"}`,
			idx%5, auditActions[idx%len(auditActions)], auditTargets[idx%len(auditTargets)], idx*317,
			auditChanges[idx%len(auditChanges)], (idx*3)%256, (idx%28)+1, idx%24, idx%60)
	default:
		s = fmt.Sprintf(`{"index":%d,"topic":"%s"}`, idx, topic)
	}
	return []byte(s)
}

func adminPerm(idx int) string {
	if idx%3 == 0 {
		return `,"admin"`
	}
	return ""
}

var fakeB64Passwords = []string{
	"dGhyZWF0LmdnLWZha2U=", "cHJvZC1zZWNyZXQtMQ==",
	"YWRtaW4tc3ZjLWtleQ==", "aW50ZXJuYWwtdG9rZW4=",
	"ZGItcGFzc3dvcmQtMjY=", "cmVkaXMtYXV0aC1rZXk=",
	"czMtYWNjZXNzLXRvaw==", "and0LXNpZ25pbmcta2V5",
	"YXBpLWdhdGV3YXktdGs=", "dmF1bHQtdW5zZWFsLWs=",
}

var alertTypes = []string{"security_alert", "access_violation", "rate_limit", "brute_force", "privilege_escalation"}
var severities = []string{"high", "critical", "medium", "high", "critical"}
var alertMessages = []string{
	"Failed login attempts exceeded threshold",
	"Unauthorized API key usage detected",
	"Unusual data export volume from PII tables",
	"SSH brute force from external IP",
	"Role escalation attempt blocked",
	"Expired certificate used in mTLS handshake",
	"Database query volume anomaly detected",
}

var piiTables = []string{
	"users,addresses,payment_methods",
	"customers,orders,shipping_addresses",
	"employees,salaries,bank_accounts",
	"patients,medical_records,insurance",
	"members,subscriptions,billing_info",
}

var auditActions = []string{
	"user.role.update", "user.delete", "api_key.create",
	"database.export", "config.update", "firewall.rule.modify",
	"secret.rotate", "user.mfa.disable",
}
var auditTargets = []string{"user", "api_key", "database", "config", "role", "secret"}
var auditChanges = []string{
	`{"role":["viewer","admin"]}`,
	`{"mfa":["enabled","disabled"]}`,
	`{"access":["read","read,write,admin"]}`,
	`{"status":["active","suspended"]}`,
	`{"permissions":["default","superuser"]}`,
}

// buildMessageV0 builds a single Kafka v0 MessageSet entry.
// Wire format: offset(8) + messageSize(4) + CRC(4) + magic(1) + attrs(1) + key(4/-1) + value(4+N)
func buildMessageV0(offset int64, key, value []byte) []byte {
	// Message body (after CRC): magic(1) + attributes(1) + key + value
	msgBody := make([]byte, 0, 2+4+len(value)+4)
	msgBody = append(msgBody, 0) // magic = 0
	msgBody = append(msgBody, 0) // attributes = 0 (no compression)

	// key: -1 for null
	if key == nil {
		msgBody = binary.BigEndian.AppendUint32(msgBody, 0xFFFFFFFF) // -1
	} else {
		msgBody = binary.BigEndian.AppendUint32(msgBody, uint32(len(key)))
		msgBody = append(msgBody, key...)
	}

	// value
	msgBody = binary.BigEndian.AppendUint32(msgBody, uint32(len(value)))
	msgBody = append(msgBody, value...)

	checksum := crc32.ChecksumIEEE(msgBody)
	messageSize := int32(4 + len(msgBody)) // CRC + msgBody

	buf := make([]byte, 0, 8+4+4+len(msgBody))
	buf = binary.BigEndian.AppendUint64(buf, uint64(offset))
	buf = binary.BigEndian.AppendUint32(buf, uint32(messageSize))
	buf = binary.BigEndian.AppendUint32(buf, checksum)
	buf = append(buf, msgBody...)
	return buf
}
