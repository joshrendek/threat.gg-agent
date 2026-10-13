package rdp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
	gproto "google.golang.org/protobuf/proto"
)

const (
	defaultPort  = "3389"
	totalTimeout = 60 * time.Second
)

var _ honeypots.Honeypot = &honeypot{}

// saveRdpConnect is a narrow seam for the one asynchronous persistence call.
var saveRdpConnect = persistence.SaveRdpConnect

type honeypot struct {
	port    string
	persona *rdpPersona
	logger  zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{
		logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "rdp").Logger(),
	}
}

func (h *honeypot) Name() string { return "rdp" }

func (h *honeypot) Start() {
	port := os.Getenv("RDP_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	h.port = port

	personaDir := os.Getenv("RDP_PERSONA_DIR")
	if personaDir == "" {
		personaDir = "/var/lib/threatgg/rdp"
	}
	persona, err := loadOrCreatePersona(personaDir)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to load RDP persona")
	}
	h.persona = persona

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start rdp listener")
	}
	h.logger.Info().Str("addr", addr).Msg("starting rdp honeypot")

	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("accept error")
			continue
		}
		go h.handleConnection(conn)
	}
}

const (
	stageTCP          = "tcp"
	stageX224         = "x224"
	stageNegotiated   = "negotiated"
	stageTLS          = "tls"
	stageCredSSP      = "credssp"
	stageChallenge    = "challenge"
	stageCapabilities = "capabilities"
	stageAuthenticate = "authenticate"
)

var stageOrder = [...]string{
	stageTCP, stageX224, stageNegotiated, stageTLS, stageCredSSP,
	stageChallenge, stageCapabilities, stageAuthenticate,
}

type session struct {
	guid               string
	remoteIP           string
	cookieUsername     string
	requestedProtocols uint32
	hasNegReq          bool
	selectedProtocol   uint32
	selectedLabel      string
	reachedStage       string
	failureClass       string
	startedAt          time.Time
	deadline           time.Time
	bytesRead          int64
	clientFingerprint  string
	tlsFingerprint     string
	tlsVersion         uint16
	tlsCipherSuite     uint16
	ntlmResult         ntlmCaptureResult
	client             *clientData
	persona            *rdpPersona
	logger             zerolog.Logger
}

func (s *session) advance(stage string) {
	current := -1
	for i, candidate := range stageOrder {
		if candidate == s.reachedStage {
			current = i
			break
		}
	}
	next := -1
	for i, candidate := range stageOrder {
		if candidate == stage {
			next = i
			break
		}
	}
	if next > current {
		s.reachedStage = stage
	}
}

func (s *session) fail(err error) {
	if err == nil || s.failureClass != "" {
		return
	}
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout():
		s.failureClass = ntlmFailureDeadline
	case errors.Is(err, net.ErrClosed):
		s.failureClass = ntlmFailureClosed
	default:
		s.failureClass = ntlmFailureProtocol
	}
}

func (h *honeypot) handleConnection(conn net.Conn) {
	if conn == nil {
		return
	}
	defer conn.Close()

	started := time.Now()
	deadline := started.Add(totalTimeout)
	remoteIP := ""
	if addr := conn.RemoteAddr(); addr != nil {
		remoteIP, _, _ = net.SplitHostPort(addr.String())
		if remoteIP == "" {
			remoteIP = addr.String()
		}
	}
	persona := h.persona
	sess := &session{
		guid:         uuid.NewV4().String(),
		remoteIP:     remoteIP,
		startedAt:    started,
		deadline:     deadline,
		reachedStage: stageTCP,
		persona:      persona,
		logger:       h.logger,
	}
	counted := &countingConn{Conn: conn}
	defer func() {
		sess.bytesRead = counted.read
		persistSession(sess)
	}()

	if persona == nil {
		sess.failureClass = "persona"
		return
	}
	if err := conn.SetDeadline(deadline); err != nil {
		sess.fail(err)
		return
	}

	payload, err := readTPKT(counted)
	if err != nil {
		sess.fail(err)
		return
	}
	sess.advance(stageTCP)
	x224Req, err := parseX224Request(payload)
	if err != nil {
		sess.fail(err)
		return
	}
	sess.advance(stageX224)
	sess.cookieUsername = x224Req.cookie
	sess.requestedProtocols = x224Req.requestedProtocols
	sess.hasNegReq = x224Req.hasNegReq

	selected, err := selectProtocol(*x224Req)
	if err != nil {
		sess.fail(err)
		return
	}
	sess.selectedProtocol = selected
	sess.selectedLabel = protocolLabel(selected)
	sess.clientFingerprint = clientFingerprint(*x224Req, selected, nil)
	if err := writeX224Confirm(counted, selected); err != nil {
		sess.fail(err)
		return
	}
	sess.advance(stageNegotiated)

	switch selected {
	case protocolHybrid:
		h.runHybrid(counted, sess)
	case protocolSSL:
		h.runSSL(counted, sess)
	default:
		h.runStandard(counted, sess)
	}
}

func protocolLabel(protocol uint32) string {
	switch protocol {
	case protocolSSL:
		return "tls"
	case protocolHybrid:
		return "hybrid"
	default:
		return "rdp"
	}
}

func (h *honeypot) runHybrid(conn net.Conn, sess *session) {
	result := captureNTLM(NTLMCaptureInput{
		Conn:            conn,
		Certificate:     sess.persona.tlsCert,
		PersonaHostname: sess.persona.hostname,
		PersonaDomain:   sess.persona.domain,
		Deadline:        sess.deadline,
	})
	sess.ntlmResult = result
	sess.tlsFingerprint = result.TLSFingerprint
	sess.tlsVersion = result.TLSVersion
	sess.tlsCipherSuite = result.TLSCipherSuite
	if result.TLSVersion != 0 {
		sess.advance(stageTLS)
	}
	if result.CredSSPSeen {
		sess.advance(stageCredSSP)
	}
	if result.ChallengeSent {
		sess.advance(stageChallenge)
	}
	if len(result.Attempts) != 0 {
		sess.advance(stageAuthenticate)
	}
	if result.FailureClass != "" {
		sess.failureClass = result.FailureClass
	}
}

func (h *honeypot) runSSL(conn net.Conn, sess *session) {
	tlsResult := captureTLS(tlsCaptureInput{
		Conn:        conn,
		Certificate: sess.persona.tlsCert,
		Deadline:    sess.deadline,
	})
	sess.tlsFingerprint = tlsResult.TLSFingerprint
	sess.tlsVersion = tlsResult.TLSVersion
	sess.tlsCipherSuite = tlsResult.TLSCipherSuite
	if tlsResult.TLSVersion == 0 {
		sess.failureClass = tlsResult.FailureClass
		return
	}
	sess.advance(stageTLS)
	defer tlsResult.Conn.Close()
	sess.readMCS(tlsResult.Conn)
}

func (h *honeypot) runStandard(conn net.Conn, sess *session) {
	sess.readMCS(conn)
}

func (s *session) readMCS(conn ioReader) {
	payload, err := readBoundedConnection(conn)
	if err != nil {
		s.fail(err)
		return
	}
	data, err := parseMCSClientData(payload)
	if err != nil {
		s.fail(err)
		return
	}
	s.client = data
	s.clientFingerprint = clientFingerprint(x224Request{hasNegReq: s.hasNegReq, requestedProtocols: s.requestedProtocols}, s.selectedProtocol, data)
	s.advance(stageCapabilities)
}

// ioReader is the narrow reader required by readBoundedConnection.
type ioReader interface{ Read([]byte) (int, error) }

func persistSession(sess *session) {
	if sess == nil {
		return
	}
	req := buildRdpRequest(sess)
	immutable := cloneRdpRequest(req)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				sess.logger.Error().Msg("panic saving rdp telemetry")
			}
		}()
		if err := saveRdpConnect(immutable); err != nil {
			sess.logger.Error().Err(err).Msg("error saving rdp telemetry")
		}
	}()
}

func buildRdpRequest(sess *session) *proto.RdpRequest {
	result := sess.ntlmResult
	selectedLabel := sess.selectedLabel
	if selectedLabel == "" {
		selectedLabel = protocolLabel(sess.selectedProtocol)
	}
	tlsVersion, tlsCipher := sess.tlsVersion, sess.tlsCipherSuite
	if tlsVersion == 0 {
		tlsVersion = result.TLSVersion
	}
	if tlsCipher == 0 {
		tlsCipher = result.TLSCipherSuite
	}
	tlsFingerprint := sess.tlsFingerprint
	if tlsFingerprint == "" {
		tlsFingerprint = result.TLSFingerprint
	}
	bytesRead := sess.bytesRead
	if result.BytesRead > bytesRead {
		bytesRead = result.BytesRead
	}
	failureClass := sess.failureClass
	if failureClass == "" {
		failureClass = result.FailureClass
	}
	req := &proto.RdpRequest{
		RemoteAddr:         sess.remoteIP,
		Guid:               sess.guid,
		RequestedProtocols: sess.requestedProtocols,
		CookieUsername:     sanitizeRdpUsername(sess.cookieUsername),
		SelectedProtocol:   selectedLabel,
		ReachedStage:       sess.reachedStage,
		FailureClass:       failureClass,
		ClientFingerprint:  sess.clientFingerprint,
		TlsFingerprint:     tlsFingerprint,
		TlsVersion:         tls.VersionName(tlsVersion),
		TlsCipher:          tls.CipherSuiteName(tlsCipher),
		PersonaId:          sess.personaID(),
		ServerHostname:     sess.personaHostname(),
		ServerDomain:       sess.personaDomain(),
	}
	if !sess.startedAt.IsZero() {
		req.DurationMs = boundedUint32(time.Since(sess.startedAt).Milliseconds())
	}
	req.BytesRead = boundedInt64Uint32(bytesRead)
	if result.CredSSPVersion != 0 {
		req.CredsspVersion = fmt.Sprintf("%d", result.CredSSPVersion)
	}
	req.SpnegoMechanism = result.SPNEGOMechanism
	req.NtlmNegotiateFlags = result.Type1Flags
	req.RetryCount = boundedUint32(int64(len(result.Attempts) - 1))
	if tlsVersion == 0 {
		req.TlsVersion = ""
		req.TlsCipher = ""
	}
	for _, attempt := range result.Attempts {
		req.AuthAttempts = append(req.AuthAttempts, &proto.RdpAuthAttempt{
			Guid:               attempt.GUID,
			Username:           attempt.Username,
			Domain:             attempt.Domain,
			Workstation:        attempt.Workstation,
			NtlmHash:           attempt.Hash,
			NtlmFlags:          attempt.Type3Flags,
			NtlmVersion:        attempt.NTLMVersion,
			MicPresent:         attempt.MIC,
			LmResponseKind:     attempt.LMClass,
			ObservedAtOffsetMs: attempt.ObservedAtOffsetMs,
		})
	}
	if len(result.Attempts) != 0 {
		first := result.Attempts[0]
		req.NtlmUsername = sanitizeRdpUsername(first.Username)
		req.NtlmDomain = first.Domain
		req.NtlmWorkstation = first.Workstation
		req.NtlmHash = first.Hash
		req.NtlmAuthenticateFlags = first.Type3Flags
		req.NtlmVersion = first.NTLMVersion
		req.NtlmMicPresent = first.MIC
		req.LmResponseKind = first.LMClass
	}
	if client := sess.client; client != nil {
		req.OsVersion = fmt.Sprintf("%d", client.Build)
		req.ClientBuild = fmt.Sprintf("%d", client.ClientBuild)
		req.DesktopWidth = uint32(client.DesktopWidth)
		req.DesktopHeight = uint32(client.DesktopHeight)
		req.KeyboardLayout = client.KeyboardLayout
		req.ClientName = client.ClientName
		req.VirtualChannels = append([]string(nil), client.Channels...)
	}
	return req
}

func (s *session) personaID() string {
	if s.persona == nil {
		return ""
	}
	return s.persona.id
}
func (s *session) personaHostname() string {
	if s.persona == nil {
		return ""
	}
	return s.persona.hostname
}
func (s *session) personaDomain() string {
	if s.persona == nil {
		return ""
	}
	return s.persona.domain
}

func cloneRdpRequest(in *proto.RdpRequest) *proto.RdpRequest {
	if in == nil {
		return nil
	}
	return gproto.Clone(in).(*proto.RdpRequest)
}

func boundedUint32(value int64) uint32 {
	if value <= 0 {
		return 0
	}
	if value > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

func boundedInt64Uint32(value int64) uint32 { return boundedUint32(value) }
