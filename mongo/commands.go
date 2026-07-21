package mongo

import (
	"strings"
	"time"
)

const (
	// serverVersion is the fake MongoDB version advertised by buildInfo and hello.
	serverVersion = "7.0.5"
	// maxWireVersion 21 corresponds to MongoDB 7.x, so modern drivers speak OP_MSG.
	maxWireVersion      = 21
	maxBsonObjectSize   = 16 * 1024 * 1024
	maxMessageSizeBytes = 48000000
	maxWriteBatchSize   = 100000
)

// helloResponse builds the BSON body for isMaster/hello/ismaster. It advertises a
// standalone writable primary running a modern wire version so drivers proceed to
// authenticate (where we capture credentials). Both the legacy `ismaster` and modern
// `isWritablePrimary` fields are set for compatibility across driver generations, and a
// fake `version` string is included to satisfy banner fingerprinters.
func helloResponse() []byte {
	var b bsonBuilder
	b.addBool("ismaster", true)
	b.addBool("isWritablePrimary", true)
	b.addBool("helloOk", true)
	b.addInt32("maxBsonObjectSize", maxBsonObjectSize)
	b.addInt32("maxMessageSizeBytes", maxMessageSizeBytes)
	b.addInt32("maxWriteBatchSize", maxWriteBatchSize)
	b.addDateTime("localTime", time.Now().UTC())
	b.addInt32("logicalSessionTimeoutMinutes", 30)
	b.addInt32("connectionId", 17)
	b.addInt32("minWireVersion", 0)
	b.addInt32("maxWireVersion", maxWireVersion)
	b.addBool("readOnly", false)
	b.addString("version", serverVersion)
	b.addDouble("ok", 1.0)
	return b.build()
}

// buildInfoResponse answers the buildInfo command with a plausible version document.
func buildInfoResponse() []byte {
	var b bsonBuilder
	b.addString("version", serverVersion)
	b.addString("gitVersion", "1b3b0e5b3a0c5e0d9f2a1c4b6e8d7f0a2c4e6b8d")
	b.addString("sysInfo", "deprecated")
	b.addBool("debug", false)
	b.addInt32("bits", 64)
	b.addInt32("maxBsonObjectSize", maxBsonObjectSize)
	b.addDouble("ok", 1.0)
	return b.build()
}

// okResponse is the generic {ok: 1.0} acknowledgement.
func okResponse() []byte {
	var b bsonBuilder
	b.addDouble("ok", 1.0)
	return b.build()
}

// authFailedResponse mimics MongoDB's reply to invalid credentials so a scanner records a
// realistic "auth required, creds rejected" outcome after we have captured the attempt.
func authFailedResponse() []byte {
	var b bsonBuilder
	b.addDouble("ok", 0.0)
	b.addString("errmsg", "Authentication failed.")
	b.addInt32("code", 18)
	b.addString("codeName", "AuthenticationFailed")
	return b.build()
}

// commandResponse selects the BSON body to reply with for a parsed command document.
func commandResponse(cmdName string, doc bsonDocument) []byte {
	switch strings.ToLower(cmdName) {
	case "ismaster", "hello":
		return helloResponse()
	case "buildinfo":
		return buildInfoResponse()
	case "saslstart", "saslcontinue", "authenticate":
		return authFailedResponse()
	default:
		// ping, whatsmyuri, getnonce, listDatabases, and anything else: keep the attacker
		// engaged with a bare success rather than tipping them off with an error.
		return okResponse()
	}
}

// extractCredentials pulls a best-effort username/password/mechanism out of an auth
// command. SCRAM hides the password (only the username appears in the client-first
// message); PLAIN carries both in the SASL payload; legacy authenticate carries the
// username directly.
func extractCredentials(cmdName string, doc bsonDocument) (username, password, mechanism string) {
	if v, ok := doc.lookup("mechanism"); ok {
		mechanism = v.str
	}

	switch strings.ToLower(cmdName) {
	case "authenticate":
		if v, ok := doc.lookup("user"); ok {
			username = v.str
		}
		return username, password, mechanism
	case "saslstart":
		payload, ok := doc.lookup("payload")
		if !ok {
			return username, password, mechanism
		}
		if strings.EqualFold(mechanism, "PLAIN") {
			username, password = parsePlainPayload(payload.bin)
		} else {
			username = parseScramUsername(payload.bin)
		}
	}
	return username, password, mechanism
}

// parsePlainPayload decodes a SASL PLAIN payload: authzid \x00 authcid \x00 passwd.
func parsePlainPayload(payload []byte) (user, pass string) {
	parts := strings.Split(string(payload), "\x00")
	if len(parts) >= 3 {
		return parts[1], parts[2]
	}
	return "", ""
}

// parseScramUsername extracts the username from a SCRAM client-first message. The payload
// is "<gs2-header>n=<user>,r=<nonce>"; we read the first n= attribute after the header.
func parseScramUsername(payload []byte) string {
	s := string(payload)
	// Strip the gs2 header ("n,,", "y,,", or "p=tls-...,,") up to the first ",,".
	if idx := strings.Index(s, ",,"); idx != -1 {
		s = s[idx+2:]
	}
	for _, attr := range strings.Split(s, ",") {
		if strings.HasPrefix(attr, "n=") {
			// SCRAM encodes '=' as =3D and ',' as =2C in usernames; reverse that.
			name := strings.TrimPrefix(attr, "n=")
			name = strings.ReplaceAll(name, "=2C", ",")
			name = strings.ReplaceAll(name, "=3D", "=")
			return name
		}
	}
	return ""
}

// extractClientVersion reads the driver identity from the hello client metadata
// (client.driver.name + version), used to populate MongoConnectRequest.ClientVersion.
func extractClientVersion(doc bsonDocument) string {
	client, ok := doc.lookup("client")
	if !ok || client.Type != bsonTypeDocument {
		return ""
	}
	driver, ok := client.doc.lookup("driver")
	if !ok || driver.Type != bsonTypeDocument {
		// Fall back to the application name if there is no driver block.
		if app, ok := client.doc.lookup("application"); ok && app.Type == bsonTypeDocument {
			if name, ok := app.doc.lookup("name"); ok {
				return name.str
			}
		}
		return ""
	}
	name, _ := driver.doc.lookup("name")
	version, _ := driver.doc.lookup("version")
	switch {
	case name.str != "" && version.str != "":
		return name.str + " " + version.str
	case name.str != "":
		return name.str
	default:
		return version.str
	}
}
