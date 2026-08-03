// Package adb emulates a bounded Android Debug Bridge device transport.
package adb

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort        = "5555"
	adbVersion         = 0x01000000
	advertisedPayload  = 256 << 10
	maxWirePayload     = 1 << 20
	maxHostBanner      = 4096
	maxServices        = 128
	maxCommands        = 128
	maxCommandBytes    = 4096
	maxUploadBytes     = 64 << 20
	maxConnections     = 128
	idleTimeout        = 90 * time.Second
	connectionTimeout  = 10 * time.Minute
	commandLookupLimit = time.Second

	cmdCNXN = 0x4e584e43
	cmdOPEN = 0x4e45504f
	cmdOKAY = 0x59414b4f
	cmdCLSE = 0x45534c43
	cmdWRTE = 0x45545257
	cmdAUTH = 0x48545541

	authToken     = 1
	authSignature = 2
	authPublicKey = 3
)

var saveSession = persistence.SaveAdbSession
var saveFile = persistence.SaveFile
var getCommandResponse = persistence.GetCommandResponseWithin
var connectionSlots = make(chan struct{}, maxConnections)
var persistenceSlots = make(chan struct{}, 32)
var fileSlots = make(chan struct{}, 8)

type honeypot struct{ logger zerolog.Logger }

// New constructs the Android Debug Bridge honeypot.
func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "adb").Logger()}
}
func (h *honeypot) Name() string { return "adb" }
func (h *honeypot) Start() {
	port := os.Getenv("ADB_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start ADB listener")
	}
	h.logger.Info().Str("port", port).Msg("starting ADB honeypot")
	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("ADB accept failed")
			continue
		}
		select {
		case connectionSlots <- struct{}{}:
			go func() { defer func() { <-connectionSlots }(); h.handleConnection(conn) }()
		default:
			_ = conn.Close()
		}
	}
}

type message struct {
	command, arg0, arg1 uint32
	data                []byte
}

type channel struct {
	clientID, deviceID uint32
	service            string
	interactive        bool
	closeAfterAck      bool
	sync               syncState
}

type syncState struct {
	buffer   []byte
	filename string
	data     []byte
	dropped  bool
}

type session struct {
	guid, remote, hostBanner, authKind, authFingerprint string
	protocolVersion, maxPayload                         uint32
	services, commands                                  []string
	channels                                            map[uint32]*channel
	nextDeviceID                                        uint32
	authPending                                         bool
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	s := &session{guid: uuid.NewV4().String(), remote: host, channels: make(map[uint32]*channel), nextDeviceID: 1}
	defer persist(s)
	_ = conn.SetDeadline(time.Now().Add(connectionTimeout))
	for i := 0; i < 4096; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		msg, err := readMessage(conn)
		if err != nil {
			return
		}
		if !s.handleMessage(conn, msg) {
			return
		}
	}
}

func (s *session) handleMessage(conn net.Conn, msg message) bool {
	switch msg.command {
	case cmdCNXN:
		s.protocolVersion = msg.arg0
		s.maxPayload = msg.arg1
		s.hostBanner = boundedText(msg.data, maxHostBanner)
		challenge := make([]byte, 20)
		if _, err := rand.Read(challenge); err != nil {
			return false
		}
		s.authPending = true
		return writeMessage(conn, message{command: cmdAUTH, arg0: authToken, data: challenge}) == nil
	case cmdAUTH:
		if !s.authPending || (msg.arg0 != authSignature && msg.arg0 != authPublicKey) {
			return true
		}
		s.authKind = map[bool]string{true: "public-key", false: "signature"}[msg.arg0 == authPublicKey]
		s.authFingerprint = fingerprintAuth(msg.data, msg.arg0 == authPublicKey)
		s.authPending = false
		return writeMessage(conn, message{command: cmdCNXN, arg0: adbVersion, arg1: advertisedPayload, data: []byte(deviceBanner())}) == nil
	case cmdOPEN:
		return s.openChannel(conn, msg)
	case cmdWRTE:
		return s.writeChannel(conn, msg)
	case cmdOKAY:
		ch := s.channels[msg.arg1]
		if ch != nil && ch.closeAfterAck {
			ch.closeAfterAck = false
			_ = writeMessage(conn, message{command: cmdCLSE, arg0: ch.deviceID, arg1: ch.clientID})
			delete(s.channels, ch.deviceID)
		}
		return true
	case cmdCLSE:
		ch := s.channels[msg.arg1]
		if ch != nil {
			_ = writeMessage(conn, message{command: cmdCLSE, arg0: ch.deviceID, arg1: ch.clientID})
			delete(s.channels, ch.deviceID)
		}
		return true
	default:
		return false
	}
}

func (s *session) openChannel(conn net.Conn, msg message) bool {
	service := strings.TrimRight(boundedText(msg.data, maxCommandBytes), "\x00")
	if service == "" || len(s.channels) >= 64 {
		return false
	}
	deviceID := s.nextDeviceID
	s.nextDeviceID++
	ch := &channel{clientID: msg.arg0, deviceID: deviceID, service: service}
	s.channels[deviceID] = ch
	s.addService(service)
	if err := writeMessage(conn, message{command: cmdOKAY, arg0: deviceID, arg1: msg.arg0}); err != nil {
		return false
	}

	switch {
	case strings.HasPrefix(service, "shell:") || strings.HasPrefix(service, "exec:"):
		command := service[strings.IndexByte(service, ':')+1:]
		if command == "" {
			ch.interactive = true
			return s.sendChannelData(conn, ch, []byte("shell@pixel7:/ $ "), false)
		}
		return s.runCommand(conn, ch, command, true)
	case strings.HasPrefix(service, "shell,"):
		colon := strings.IndexByte(service, ':')
		command := ""
		if colon >= 0 {
			command = service[colon+1:]
		}
		if command == "" {
			ch.interactive = true
			return s.sendChannelData(conn, ch, []byte("shell@pixel7:/ $ "), false)
		}
		return s.runCommand(conn, ch, command, true)
	case service == "sync:":
		return true
	case strings.HasPrefix(service, "tcp:") || strings.HasPrefix(service, "localabstract:") || strings.HasPrefix(service, "localfilesystem:"):
		ch.closeAfterAck = false
		_ = writeMessage(conn, message{command: cmdCLSE, arg0: ch.deviceID, arg1: ch.clientID})
		delete(s.channels, ch.deviceID)
		return true
	default:
		_ = writeMessage(conn, message{command: cmdCLSE, arg0: ch.deviceID, arg1: ch.clientID})
		delete(s.channels, ch.deviceID)
		return true
	}
}

func (s *session) writeChannel(conn net.Conn, msg message) bool {
	ch := s.channels[msg.arg1]
	if ch == nil || msg.arg0 != ch.clientID {
		return false
	}
	if err := writeMessage(conn, message{command: cmdOKAY, arg0: ch.deviceID, arg1: ch.clientID}); err != nil {
		return false
	}
	if ch.service == "sync:" {
		return s.handleSync(conn, ch, msg.data)
	}
	if ch.interactive {
		for _, line := range strings.Split(strings.ReplaceAll(string(msg.data), "\r", ""), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !s.runCommand(conn, ch, line, false) {
				return false
			}
		}
	}
	return true
}

func (s *session) runCommand(conn net.Conn, ch *channel, command string, closeAfter bool) bool {
	command = boundedText([]byte(strings.TrimSpace(command)), maxCommandBytes)
	if command == "" {
		return true
	}
	s.addCommand(command)
	response := defaultCommandResponse(command)
	if result, err := getCommandResponse(&pb.CommandRequest{Command: command, CommandType: "adb"}, commandLookupLimit); err == nil && result.Matched {
		response = result.Response
	}
	if !strings.HasSuffix(response, "\n") {
		response += "\n"
	}
	if !closeAfter {
		response += "shell@pixel7:/ $ "
	}
	return s.sendChannelData(conn, ch, []byte(response), closeAfter)
}

func (s *session) sendChannelData(conn net.Conn, ch *channel, data []byte, closeAfter bool) bool {
	if len(data) > advertisedPayload {
		data = data[:advertisedPayload]
	}
	if err := writeMessage(conn, message{command: cmdWRTE, arg0: ch.deviceID, arg1: ch.clientID, data: data}); err != nil {
		return false
	}
	ch.closeAfterAck = closeAfter
	return true
}

func (s *session) handleSync(conn net.Conn, ch *channel, data []byte) bool {
	if len(ch.sync.buffer)+len(data) > maxWirePayload+8 {
		return false
	}
	ch.sync.buffer = append(ch.sync.buffer, data...)
	for len(ch.sync.buffer) >= 8 {
		id := string(ch.sync.buffer[:4])
		n := binary.LittleEndian.Uint32(ch.sync.buffer[4:8])
		if id == "DONE" || id == "QUIT" {
			ch.sync.buffer = ch.sync.buffer[8:]
			if id == "DONE" {
				s.finishUpload(ch)
				var ok [8]byte
				copy(ok[:4], "OKAY")
				if !s.sendChannelData(conn, ch, ok[:], false) {
					return false
				}
			} else {
				_ = writeMessage(conn, message{command: cmdCLSE, arg0: ch.deviceID, arg1: ch.clientID})
				delete(s.channels, ch.deviceID)
				return true
			}
			continue
		}
		if n > maxWirePayload || int(n) > len(ch.sync.buffer)-8 {
			if n > maxWirePayload {
				return false
			}
			break
		}
		payload := ch.sync.buffer[8 : 8+int(n)]
		ch.sync.buffer = ch.sync.buffer[8+int(n):]
		switch id {
		case "SEND":
			spec := boundedText(payload, maxHostBanner)
			filename := spec
			if comma := strings.LastIndexByte(filename, ','); comma >= 0 {
				filename = filename[:comma]
			}
			ch.sync.filename = safeFilename(filename)
			ch.sync.data = nil
			ch.sync.dropped = false
			s.addService("sync:push " + boundedText([]byte(filename), maxHostBanner))
		case "DATA":
			if len(ch.sync.data)+len(payload) <= maxUploadBytes && !ch.sync.dropped {
				ch.sync.data = append(ch.sync.data, payload...)
			} else {
				ch.sync.data = nil
				ch.sync.dropped = true
			}
		case "STAT":
			var stat [16]byte
			copy(stat[:4], "STAT")
			if !s.sendChannelData(conn, ch, stat[:], false) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *session) finishUpload(ch *channel) {
	if ch.sync.filename == "" || len(ch.sync.data) == 0 || ch.sync.dropped {
		return
	}
	data := append([]byte(nil), ch.sync.data...)
	filename, guid := ch.sync.filename, s.guid
	select {
	case fileSlots <- struct{}{}:
		save := saveFile
		go func() { defer func() { <-fileSlots }(); _ = save(data, filename, guid, "adb-sync") }()
	default:
	}
	ch.sync.data = nil
}

func (s *session) addService(value string) {
	if len(s.services) < maxServices {
		s.services = append(s.services, boundedText([]byte(value), maxCommandBytes))
	}
}
func (s *session) addCommand(value string) {
	if len(s.commands) < maxCommands {
		s.commands = append(s.commands, boundedText([]byte(value), maxCommandBytes))
	}
}

func persist(s *session) {
	if s.protocolVersion == 0 {
		return
	}
	in := &pb.AdbSessionRequest{RemoteAddr: boundedText([]byte(s.remote), 128), Guid: s.guid,
		HostBanner: s.hostBanner, AuthKind: s.authKind, AuthFingerprint: s.authFingerprint,
		ProtocolVersion: s.protocolVersion, MaxPayload: s.maxPayload,
		Services: append([]string(nil), s.services...), Commands: append([]string(nil), s.commands...)}
	select {
	case persistenceSlots <- struct{}{}:
		save := saveSession
		go func() { defer func() { <-persistenceSlots }(); _ = save(in) }()
	default:
	}
}

func readMessage(r io.Reader) (message, error) {
	var header [24]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return message{}, err
	}
	cmd := binary.LittleEndian.Uint32(header[0:4])
	n := binary.LittleEndian.Uint32(header[12:16])
	wantChecksum := binary.LittleEndian.Uint32(header[16:20])
	magic := binary.LittleEndian.Uint32(header[20:24])
	if magic != cmd^0xffffffff {
		return message{}, errors.New("invalid ADB command magic")
	}
	if n > maxWirePayload {
		return message{}, errors.New("ADB payload is too large")
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return message{}, err
	}
	if wantChecksum != 0 && checksum(data) != wantChecksum {
		return message{}, errors.New("invalid ADB payload checksum")
	}
	return message{command: cmd, arg0: binary.LittleEndian.Uint32(header[4:8]), arg1: binary.LittleEndian.Uint32(header[8:12]), data: data}, nil
}

func writeMessage(w io.Writer, msg message) error {
	if len(msg.data) > maxWirePayload {
		return errors.New("ADB payload is too large")
	}
	var header [24]byte
	binary.LittleEndian.PutUint32(header[0:4], msg.command)
	binary.LittleEndian.PutUint32(header[4:8], msg.arg0)
	binary.LittleEndian.PutUint32(header[8:12], msg.arg1)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(msg.data)))
	binary.LittleEndian.PutUint32(header[16:20], checksum(msg.data))
	binary.LittleEndian.PutUint32(header[20:24], msg.command^0xffffffff)
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, msg.data)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func checksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

func fingerprintAuth(data []byte, publicKey bool) string {
	material := data
	if publicKey {
		fields := strings.Fields(strings.TrimRight(string(data), "\x00"))
		if len(fields) > 0 {
			if decoded, err := base64.StdEncoding.DecodeString(fields[0]); err == nil {
				material = decoded
			}
		}
	}
	sum := sha256.Sum256(material)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func boundedText(data []byte, limit int) string {
	value := strings.ToValidUTF8(string(data), "�")
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}

func safeFilename(value string) string {
	value = path.Base(strings.ReplaceAll(value, "\\", "/"))
	value = boundedText([]byte(value), 255)
	if value == "" || value == "." || value == "/" {
		return "adb-upload.bin"
	}
	return value
}

func deviceBanner() string {
	return "device::ro.product.name=panther;ro.product.model=Pixel_7;ro.product.device=panther;features=cmd"
}

func defaultCommandResponse(command string) string {
	trimmed := strings.TrimSpace(command)
	switch {
	case trimmed == "id":
		return "uid=2000(shell) gid=2000(shell) groups=1003(graphics),1004(input),1015(sdcard_rw),3003(inet) context=u:r:shell:s0\n"
	case trimmed == "whoami":
		return "shell\n"
	case trimmed == "pwd":
		return "/data/local/tmp\n"
	case trimmed == "uname -a":
		return "Linux localhost 5.10.177-android13-4 #1 SMP PREEMPT Thu Jun 20 12:00:00 UTC 2026 aarch64\n"
	case trimmed == "getprop" || strings.HasPrefix(trimmed, "getprop "):
		return "[ro.build.version.release]: [13]\n[ro.product.model]: [Pixel 7]\n[ro.product.cpu.abi]: [arm64-v8a]\n"
	case trimmed == "ls" || strings.HasPrefix(trimmed, "ls "):
		return "acct  apex  bin  bugreports  cache  config  data  dev  etc  metadata  mnt  proc  sdcard  storage  sys  system  vendor\n"
	case trimmed == "cat /proc/version":
		return "Linux version 5.10.177-android13-4 (android-build@google.com) (Android clang 14.0.7) #1 SMP PREEMPT\n"
	case trimmed == "true" || strings.HasPrefix(trimmed, "cd "):
		return ""
	default:
		name := strings.Fields(trimmed)
		if len(name) == 0 {
			return ""
		}
		return "sh: " + strconv.Quote(name[0]) + ": not found\n"
	}
}
