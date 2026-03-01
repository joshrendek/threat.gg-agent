package smb

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort    = "445"
	totalTimeout   = 120 * time.Second
	readTimeout    = 30 * time.Second
	maxIterations  = 100
)

var _ honeypots.Honeypot = &honeypot{}

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "smb").Logger()

type honeypot struct {
	logger zerolog.Logger
}

// New creates a new SMB honeypot instance.
func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "smb").Logger()}
}

func (h *honeypot) Name() string {
	return "smb"
}

func (h *honeypot) Start() {
	port := os.Getenv("SMB_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start smb listener")
	}
	h.logger.Info().Str("addr", addr).Msg("starting smb honeypot")

	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("accept error")
			continue
		}
		go h.handleConnection(conn)
	}
}

// session tracks state for a single attacker connection.
type session struct {
	guid           string
	remoteIP       string
	ntlmServer     *ntlmServer
	username       string
	domain         string
	workstation    string
	hash           string
	dialect        string
	sharesAccessed []string
	sessionID      uint64
	messageID      uint64
	authenticated  bool
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if remoteAddr == "" {
		remoteAddr = conn.RemoteAddr().String()
	}

	sess := &session{
		guid:       uuid.NewV4().String(),
		remoteIP:   remoteAddr,
		ntlmServer: newNTLMServer(),
	}

	h.logger.Info().Str("session", sess.guid).Str("remote", remoteAddr).Msg("new connection")

	// Set total connection timeout
	conn.SetDeadline(time.Now().Add(totalTimeout))

	// Step 1: Read first NetBIOS frame
	payload, err := readNetBIOSFrame(conn, readTimeout)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read initial frame")
		return
	}

	// Step 2: If SMB1, send SMB1 negotiate response and read next frame
	if isSMB1(payload) {
		h.logger.Debug().Str("session", sess.guid).Msg("received SMB1 negotiate, upgrading to SMB2")
		smb1Resp := buildSMB1NegotiateResponse()
		if err := writeNetBIOSFrame(conn, smb1Resp); err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to send SMB1 response")
			return
		}

		// Read next frame (should be SMB2 negotiate)
		payload, err = readNetBIOSFrame(conn, readTimeout)
		if err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read SMB2 negotiate")
			return
		}
	}

	// Step 3: Parse SMB2 Negotiate
	if !isSMB2(payload) {
		h.logger.Debug().Str("session", sess.guid).Msg("expected SMB2 negotiate, got unknown protocol")
		return
	}

	reqHeader, err := parseSMB2Header(payload)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to parse SMB2 header")
		return
	}

	if reqHeader.Command != smbCmdNegotiate {
		h.logger.Debug().Str("session", sess.guid).Uint16("cmd", reqHeader.Command).Msg("expected negotiate command")
		return
	}

	sess.dialect = "SMB 2.1"

	negResp := buildNegotiateResponse(reqHeader)
	if err := writeNetBIOSFrame(conn, negResp); err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to send negotiate response")
		return
	}

	// Step 4: Session Setup 1 (NTLMSSP Type 1 -> Type 2)
	payload, err = readNetBIOSFrame(conn, readTimeout)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read session setup 1")
		return
	}

	if !isSMB2(payload) {
		h.logger.Debug().Str("session", sess.guid).Msg("expected SMB2 session setup")
		return
	}

	reqHeader, err = parseSMB2Header(payload)
	if err != nil || reqHeader.Command != smbCmdSessionSetup {
		h.logger.Debug().Str("session", sess.guid).Msg("expected session setup command")
		return
	}

	// Extract NTLMSSP from SPNEGO wrapper
	ntlmData := unwrapSPNEGO(payload[smb2HeaderSize:])
	if ntlmData == nil || !isNTLMSSP(ntlmData) {
		h.logger.Debug().Str("session", sess.guid).Msg("no NTLMSSP in session setup 1")
		return
	}

	msgType := getNTLMMessageType(ntlmData)
	if msgType != ntlmNegotiate {
		h.logger.Debug().Str("session", sess.guid).Uint32("type", msgType).Msg("expected NTLMSSP negotiate (type 1)")
		return
	}

	// Build Type 2 challenge
	challengeBlob := buildType2Challenge(sess.ntlmServer)
	spnegoResp := wrapSPNEGOChallenge(challengeBlob)

	setupResp := buildSessionSetupResponse(reqHeader, spnegoResp, statusMoreProcessingRequired)
	if err := writeNetBIOSFrame(conn, setupResp); err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to send challenge")
		return
	}

	// Update session ID from the response we generated
	sess.sessionID = 0x0000400000000041

	// Step 5: Session Setup 2 (NTLMSSP Type 3 -> success)
	payload, err = readNetBIOSFrame(conn, readTimeout)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read session setup 2")
		return
	}

	if !isSMB2(payload) {
		h.logger.Debug().Str("session", sess.guid).Msg("expected SMB2 session setup 2")
		return
	}

	reqHeader, err = parseSMB2Header(payload)
	if err != nil || reqHeader.Command != smbCmdSessionSetup {
		h.logger.Debug().Str("session", sess.guid).Msg("expected session setup 2 command")
		return
	}

	ntlmData = unwrapSPNEGO(payload[smb2HeaderSize:])
	if ntlmData == nil || !isNTLMSSP(ntlmData) {
		h.logger.Debug().Str("session", sess.guid).Msg("no NTLMSSP in session setup 2")
		return
	}

	msgType = getNTLMMessageType(ntlmData)
	if msgType != ntlmAuthenticate {
		h.logger.Debug().Str("session", sess.guid).Uint32("type", msgType).Msg("expected NTLMSSP authenticate (type 3)")
		return
	}

	// Parse Type 3 authentication message
	username, domain, workstation, ntlmResponse := parseType3Auth(ntlmData)
	sess.username = username
	sess.domain = domain
	sess.workstation = workstation
	sess.hash = formatNetNTLMv2Hash(username, domain, sess.ntlmServer.challenge, ntlmResponse)
	sess.authenticated = true

	h.logger.Info().
		Str("session", sess.guid).
		Str("username", username).
		Str("domain", domain).
		Str("workstation", workstation).
		Bool("has_hash", sess.hash != "").
		Msg("NTLM authentication captured")

	// Send success response
	acceptBlob := wrapSPNEGOAccept()
	successResp := buildSessionSetupResponse(reqHeader, acceptBlob, statusSuccess)
	if err := writeNetBIOSFrame(conn, successResp); err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to send auth success")
		persistSession(sess)
		return
	}

	// Step 6: Command loop
	for i := 0; i < maxIterations; i++ {
		payload, err = readNetBIOSFrame(conn, readTimeout)
		if err != nil {
			break
		}

		if !isSMB2(payload) {
			break
		}

		reqHeader, err = parseSMB2Header(payload)
		if err != nil {
			break
		}

		var resp []byte

		switch reqHeader.Command {
		case smbCmdTreeConnect:
			uncPath := parseTreeConnectPath(payload)
			shareName := extractShareName(uncPath)

			h.logger.Debug().
				Str("session", sess.guid).
				Str("path", uncPath).
				Str("share", shareName).
				Msg("tree connect")

			shareType, known := knownShares[shareName]
			if known {
				sess.sharesAccessed = append(sess.sharesAccessed, shareName)
				resp = buildTreeConnectResponse(reqHeader, shareType)
			} else {
				resp = buildErrorResponse(reqHeader, smbCmdTreeConnect, statusBadNetworkName)
			}

		case smbCmdCreate:
			resp = buildErrorResponse(reqHeader, smbCmdCreate, statusAccessDenied)

		case smbCmdClose:
			resp = buildErrorResponse(reqHeader, smbCmdClose, statusSuccess)

		case smbCmdRead:
			resp = buildErrorResponse(reqHeader, smbCmdRead, statusAccessDenied)

		case smbCmdQueryDirectory:
			resp = buildErrorResponse(reqHeader, smbCmdQueryDirectory, statusAccessDenied)

		case smbCmdIoctl:
			resp = buildErrorResponse(reqHeader, smbCmdIoctl, statusNotSupported)

		case smbCmdLogoff:
			resp = buildErrorResponse(reqHeader, smbCmdLogoff, statusSuccess)
			writeNetBIOSFrame(conn, resp)
			goto done

		case smbCmdTreeDisconnect:
			resp = buildErrorResponse(reqHeader, smbCmdTreeDisconnect, statusSuccess)

		default:
			resp = buildErrorResponse(reqHeader, reqHeader.Command, statusNotSupported)
		}

		if err := writeNetBIOSFrame(conn, resp); err != nil {
			break
		}
	}

done:
	h.logger.Info().
		Str("session", sess.guid).
		Str("username", sess.username).
		Int("shares", len(sess.sharesAccessed)).
		Msg("session ended")

	persistSession(sess)
}

// persistSession sends session data to the server via gRPC.
func persistSession(sess *session) {
	if sess.username == "" && len(sess.sharesAccessed) == 0 {
		return // no interesting data
	}

	req := &proto.SmbRequest{
		RemoteAddr:      sess.remoteIP,
		Guid:            sess.guid,
		NtlmUsername:    sess.username,
		NtlmDomain:     sess.domain,
		NtlmWorkstation: sess.workstation,
		NtlmHash:       sess.hash,
		SmbDialect:     sess.dialect,
		SharesAccessed: sess.sharesAccessed,
		Data:           buildSessionJSON(sess),
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Interface("panic", r).Msg("panic saving smb session")
			}
		}()
		if err := persistence.SaveSmbConnect(req); err != nil {
			logger.Error().Err(err).Msg("error saving smb session")
		}
	}()
}

// sessionData is the JSON structure stored in the data field.
type sessionData struct {
	Username       string   `json:"username,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	Workstation    string   `json:"workstation,omitempty"`
	Dialect        string   `json:"dialect,omitempty"`
	SharesAccessed []string `json:"shares_accessed,omitempty"`
	HasHash        bool     `json:"has_hash"`
}

// buildSessionJSON creates a JSON summary of the session.
func buildSessionJSON(sess *session) string {
	data := sessionData{
		Username:       sess.username,
		Domain:         sess.domain,
		Workstation:    sess.workstation,
		Dialect:        sess.dialect,
		SharesAccessed: sess.sharesAccessed,
		HasHash:        sess.hash != "",
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "{}"
	}
	return string(jsonBytes)
}

// extractShareNameFromPath is a helper to get the share from an IP or hostname based UNC path.
func extractShareNameFromPath(path string) string {
	// Normalize forward slashes to backslashes
	path = strings.ReplaceAll(path, "/", "\\")
	return extractShareName(path)
}
