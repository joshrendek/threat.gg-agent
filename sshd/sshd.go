package sshd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jellydator/ttlcache/v3"

	"github.com/joshrendek/threat.gg-agent/proto"

	"github.com/joshrendek/threat.gg-agent/persistence"

	"context"
	"net"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/stats"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const DEFAULT_SHELL = "bash"

const maxExecCommandLen = 64 * 1024

// maxScpUploadBytes caps how large an SCP-pushed file we'll buffer in memory and ship
// to the server's file pipeline; matches the server's MaxDownloadBytes guard (64 MiB).
const maxScpUploadBytes = 64 << 20

// maxPtyTermLen bounds the TERM string a pty-req may declare. Real values
// are a few dozen bytes ("xterm-256color"); anything approaching this is a
// probe, not a terminal.
const maxPtyTermLen = 4096

// parsePtyRequest extracts the TERM string from a pty-req payload (RFC 4254
// §6.2: string TERM, then four uint32 dimensions, then string modes). It
// mirrors parseExecCommand because it had the same class of bug that one was
// hardened against: the inline code read Payload[3] as the length -- a single
// byte of a four-byte field -- and sliced Payload[4:termLen+4] unchecked. A
// payload under four bytes indexed out of range; a declared length past the
// end sliced out of range; and because termLen was a byte, 253+4 wrapped to 1
// and Payload[4:1] panicked even on an otherwise well-formed request
// (threat_gg-ith). Any of the three ended the process, and with it every
// honeypot on the node.
func parsePtyRequest(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", fmt.Errorf("pty-req payload is shorter than the SSH string header")
	}
	termLen := uint64(binary.BigEndian.Uint32(payload[:4]))
	if termLen > maxPtyTermLen {
		return "", fmt.Errorf("pty-req TERM length %d exceeds limit %d", termLen, maxPtyTermLen)
	}
	if termLen > uint64(len(payload)-4) {
		return "", fmt.Errorf("pty-req TERM length %d exceeds payload size %d", termLen, len(payload)-4)
	}
	return string(payload[4 : 4+int(termLen)]), nil
}

func parseExecCommand(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", fmt.Errorf("exec payload is shorter than the SSH string header")
	}

	commandLen := uint64(binary.BigEndian.Uint32(payload[:4]))
	if commandLen > maxExecCommandLen {
		return "", fmt.Errorf("exec command length %d exceeds limit %d", commandLen, maxExecCommandLen)
	}
	if commandLen > uint64(len(payload)-4) {
		return "", fmt.Errorf("exec command length %d exceeds payload size %d", commandLen, len(payload)-4)
	}

	return string(payload[4 : 4+int(commandLen)]), nil
}

var (
	logger      = zerolog.New(os.Stdout).With().Caller().Str("sshd", "").Logger()
	httpHandler = map[string][]byte{}
	t           *tor.Tor
	dialer      *tor.Dialer
	httpClient  *http.Client
	torEnabled  bool

	// saveHTTPRequest is a package var so tests can capture what the proxy
	// path persists without a gRPC client -- the saveIcsProbe/saveSession
	// pattern used elsewhere in the agent.
	saveHTTPRequest = persistence.SaveHTTPRequest
)

type honeypot struct {
	logger zerolog.Logger
}

func init() {
	torEnabled = os.Getenv("TOR_ENABLED") == "true"
}

func New() honeypots.Honeypot {
	h := &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "ftp").Logger()}
	return h
}

func (h *honeypot) Name() string {
	return "ssh"
}

func (h *honeypot) Start() {
	var err error

	if torEnabled {
		t, err = tor.Start(nil, nil)
		if err != nil {
			h.logger.Fatal().Err(err).Msg("failed to connect to tor")
		}
		dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Minute)
		defer dialCancel()
		dialer, err = t.Dialer(dialCtx, nil)
		if err != nil {
			h.logger.Fatal().Err(err).Msg("failed to connect to tor")
		}
		httpClient = &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	}

	h.generateSshKey()
	sshConfig := &ssh.ServerConfig{
		PasswordCallback:  h.passAuthCallback,
		PublicKeyCallback: h.keyAuthCallback,
		ServerVersion:     "SSH-2.0-OpenSSH_6.4p1, OpenSSL 1.0.1e-fips 11 Feb 2013", // old and vulnerable!
	}

	// You can generate a keypair with 'ssh-keygen -t rsa -C "test@example.com"'
	sshKeys := []string{"honeypot_prv", "honeypot_rsa_prv"}
	for _, sshKey := range sshKeys {
		privateBytes, err := ioutil.ReadFile(sshKey)
		if err != nil {
			h.logger.Fatal().Msgf("failed to load private key (./%s)", sshKey)
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			h.logger.Fatal().Msg("failed to parse private key")
		}

		sshConfig.AddHostKey(private)
	}

	// Accept all connections
	port := os.Getenv("SSH_PORT")
	if port == "" {
		port = "22"
	}

	// Once a ServerConfig has been configured, connections can be accepted.
	fmt.Println("listening")
	listener, err := net.Listen("tcp4", ":"+port)
	if err != nil {
		h.logger.Fatal().Str("port", port).Msg("failed to listen")
	}

	// setup http handlers
	httpHandler["ip-api.com/json"] = []byte(`{"as":"AS701 MCI Communications Services, Inc. d/b/a Verizon Business","city":"Peach","country":"United States","countryCode":"US","isp":"Verizon Fios","lat":22.9166,"lon":-44.8032,"org":"Verizon Fios","query":"13.65.94.13","region":"GA","regionName":"Georgia","status":"success","timezone":"America/New_York","zip":"12345"}`)
	httpHandler["cetinhechinhis.com/ip.php"] = []byte("45.4.123.22")
	httpHandler["www.hailsoft.net/ip.php"] = []byte("45.4.123.22")

	h.logger.Info().Str("port", port).Msg("started listening")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to accept incoming connection")
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			h.logger.Error().Err(err).Msg("failed to handshake")
			continue
		}

		// Check remote address
		h.logger.Info().Str("remote_ip", sshConn.RemoteAddr().String()).Str("client_version", string(sshConn.ClientVersion())).Msg("new ssh connection")

		// Print incoming out-of-band Requests
		go h.handleRequests(reqs)
		// Accept all channels
		go h.handleChannels(chans, sshConn.Permissions)
	}
}

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (h *honeypot) generateSshKey() {
	h.logger.Info().Msg("generating ssh keys")
	if Exists("honeypot_prv") {
		h.logger.Info().Msg("removing old keys")
		os.Remove("honeypot_rsa_prv")
		os.Remove("honeypot_rsa_prv.pub")
		os.Remove("honeypot_prv")
		os.Remove("honeypot_prv.pub")
	}

	out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-q", "-f", "honeypot_prv", "-N", "").CombinedOutput()
	if err != nil {
		h.logger.Fatal().Err(err).Str("output", string(out)).Msg("error generating key")
	}

	out, err = exec.Command("ssh-keygen", "-t", "rsa", "-q", "-f", "honeypot_rsa_prv", "-N", "").CombinedOutput()
	if err != nil {
		h.logger.Fatal().Err(err).Str("output", string(out)).Msg("error generating key")
	}
}

func (h *honeypot) handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("recieved out-of-band request: %+v", req)
	}
}

type exitStatusMsg struct {
	Status uint32
}

func HandleTcpReading(channel ssh.Channel, term *terminal.Terminal, perms *ssh.Permissions) {
	defer channel.Close()
	defer recoverChannelPanic("direct-tcpip")
	//http := map[string]string{}
	for {
		// read up to 1MB of data
		b := make([]byte, 1024*1024)
		_, err := channel.Read(b)
		if err != nil {
			if err.Error() == "EOF" {
				return
			}
		}

		stats.Increment("ssh.proxy_request")
		read := bufio.NewReader(strings.NewReader(string(b)))
		toReq, err := http.ReadRequest(read)
		// TODO: https will panic atm - need to figure this out
		if err != nil {
			log.Println("Error parsing request: ", err)
			return
		}
		err = toReq.ParseForm()
		if err != nil {
			log.Println("Error parsing form: ", err)
			return
		}
		url := fmt.Sprintf("%s%s", toReq.Host, toReq.URL)

		httpReq := &proto.HttpRequest{
			Headers:   persistence.HttpToMap(map[string][]string(toReq.Header)),
			Url:       url,
			FormData:  persistence.HttpToMap(map[string][]string(toReq.Form)),
			Method:    toReq.Method,
			UserAgent: toReq.UserAgent(),
			Guid:      perms.Extensions["guid"],
			Hostname:  toReq.Host,
		}

		user, pass, ok := toReq.BasicAuth()
		if ok {
			httpReq.Username = user
			httpReq.Password = pass
		}

		// The request IS the capture; whether we can proxy it is secondary.
		// Persist it before attempting the upstream fetch so a failure there
		// cannot cost us the observation, and attach the body afterwards if
		// one arrives.
		body := proxyUpstream(url, toReq.Header)
		if body != nil {
			httpReq.Response = base64.StdEncoding.EncodeToString(body)
		}

		// Read the hook synchronously and hand the goroutine the value. The
		// goroutine outlives this call, and a package-level var read from a
		// goroutine that outlives its caller is the race class threat_gg-x59t
		// documents in mssql -- the test that swaps the hook would otherwise
		// race with the save it is trying to observe.
		save := saveHTTPRequest
		go func(in *proto.HttpRequest) {
			if err := save(in); err != nil {
				logger.Error().Err(err).Msg("error saving http request")
			}
		}(httpReq)

		if body != nil {
			channel.Write(body)
		}
		channel.Close()
	}
}

// proxyUpstream performs the outbound fetch for a direct-tcpip proxy request
// and returns the response body, or nil when there is nothing to return.
//
// Two of threat_gg-ith's three crash vectors lived here. httpClient is only
// constructed when TOR_ENABLED=true, so with the default config it is nil and
// the first proxied request dereferenced it; and both error branches called
// log.Fatalf, so even with tor enabled a proxied request to a dead upstream
// exited the process. Neither condition is the attacker's doing, and neither
// justifies ending every honeypot on the node -- a nil client or a dead
// upstream simply means there is no body to hand back.
func proxyUpstream(url string, headers http.Header) []byte {
	if httpClient == nil {
		logger.Debug().Str("url", url).Msg("proxy request captured; no outbound client configured (TOR_ENABLED unset)")
		return nil
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", url), nil)
	if err != nil {
		logger.Debug().Err(err).Str("url", url).Msg("proxy request not forwardable")
		return nil
	}
	req.Header = headers
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Warn().Err(err).Str("url", url).Msg("proxy upstream request failed")
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Warn().Err(err).Str("url", url).Msg("proxy upstream body read failed")
		return nil
	}
	return body
}

// recoverChannelPanic contains a panic to the goroutine it happened in. This
// process is every honeypot on the node; one attacker's channel is not allowed
// to end all of them. The three known vectors are fixed individually above --
// this is the backstop for the ones not yet found, and it logs loudly so they
// get found.
func recoverChannelPanic(where string) {
	if r := recover(); r != nil {
		logger.Error().Interface("panic", r).Str("where", where).Msg("recovered panic in ssh channel handler")
		stats.Increment("ssh.recovered_panic")
	}
}

func (h *honeypot) handleChannels(chans <-chan ssh.NewChannel, perms *ssh.Permissions) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("could not accept channel")
			continue
		}

		sessionTimer := stats.NewTiming()

		var shell string
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = DEFAULT_SHELL
		}

		if newChannel.ChannelType() == "direct-tcpip" {
			term := terminal.NewTerminal(channel, "")
			go HandleTcpReading(channel, term, perms)
		}

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			defer recoverChannelPanic("session-request")
			for req := range in {
				term := terminal.NewTerminal(channel, "")

				h.logger.Info().Msgf("payload %+v\n", string(req.Payload))
				ok := false
				switch req.Type {
				// exec is used: ssh user@host 'some command'
				case "exec":
					command, parseErr := parseExecCommand(req.Payload)
					if parseErr != nil {
						h.logger.Warn().Err(parseErr).Msg("invalid ssh exec request")
						break
					}
					ok = true

					isScp := strings.Contains(command, "scp")

					if isScp {
						fmt.Println("*********************")
						h.logger.Info().Msg("****************** scp command")
						fmt.Println("*********************")

						// send 10 magic null bytes
						for i := 0; i <= 10; i++ {
							channel.Write([]byte("\x00"))
						}

						b := bufio.NewReader(channel)
						for {
							fileInfo, err := b.ReadBytes('\n')
							fmt.Println("[fileInfo] ", string(fileInfo))
							if err == io.EOF {
								break
							}
							if err != nil {
								h.logger.Error().Err(err).Msg("error reading file name from scp")
							}
							tmpFileInfo := strings.Split(string(fileInfo), " ")
							tmpFilePerms := tmpFileInfo[0]
							tmpFileBytes, err := strconv.Atoi(tmpFileInfo[1])
							if err != nil {
								h.logger.Error().Err(err).Msg("error reading file byte size from scp")
								break
							}
							tmpFileName := strings.TrimSpace(tmpFileInfo[2])

							tmpFile, err := ioutil.TempFile("/tmp", "scp")
							if err != nil {
								panic(err)
							}
							writer := bufio.NewWriter(tmpFile)
							bytesRead := 0
							// Only buffer the upload in memory when it's within the size guard, so a
							// bogus/huge size claim can't make us hold a giant buffer (we still have
							// to read+discard the bytes off the wire either way to stay in protocol).
							captureUpload := tmpFileBytes > 0 && tmpFileBytes <= maxScpUploadBytes
							var fileBuf bytes.Buffer
							if captureUpload {
								fileBuf.Grow(tmpFileBytes)
							}
							shortRead := false
							for i := 0; i <= tmpFileBytes; i++ {
								t, err := b.ReadByte()
								if err != nil {
									h.logger.Warn().Err(err).Str("filename", tmpFileName).
										Msg("scp: short read, not shipping partial capture")
									shortRead = true
									break
								}
								bytesRead++
								writer.WriteByte(t)
								// SCP sends exactly tmpFileBytes content bytes followed by a single
								// trailing status/null byte, and this loop's `<=` reads tmpFileBytes+1
								// bytes total to consume both. Only i < tmpFileBytes is real file
								// content — the final iteration (i == tmpFileBytes) is the trailing
								// byte, so it must not be shipped as part of the file.
								if captureUpload && i < tmpFileBytes {
									fileBuf.WriteByte(t)
								}
							}
							fmt.Println("->>>>>>>>>>>>>>> Wrote to: ", tmpFile.Name())

							// read the last null seperator
							b.ReadBytes('\x00')

							h.logger.Info().Str("permissions", tmpFilePerms).
								Str("filename", tmpFileName).
								Int("size-parsed", tmpFileBytes).
								Int("actual-size", bytesRead).
								Msg("received file")

							// A mid-transfer disconnect/read error must never ship a zero-padded
							// capture — the trailing bytes we didn't actually read would be silent
							// zeros, so the shipped file's sha256 wouldn't match anything the
							// attacker sent. Only ship when the full tmpFileBytes content was read
							// cleanly.
							if shortRead {
								// already logged above; nothing to ship.
							} else if captureUpload && fileBuf.Len() > 0 {
								fileData := fileBuf.Bytes()
								guid := perms.Extensions["guid"]
								go func(data []byte, filename, guid string) {
									if err := persistence.SaveFile(data, filename, guid, "scp"); err != nil {
										h.logger.Error().Err(err).Str("filename", filename).Msg("error shipping scp file upload to server")
									}
								}(fileData, tmpFileName, guid)
							} else if tmpFileBytes > maxScpUploadBytes {
								h.logger.Warn().Int("size", tmpFileBytes).Str("filename", tmpFileName).Msg("scp upload exceeds size guard, not shipping to server")
							}
							//spew.Dump("file contents: ", fileTransfer)
						}
						//spew.Dump(b.String())

						// send proper exit 0 status code back to scp/ssh
						channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 0}))
						req.Reply(true, nil) // tell the other end that we can run the request

					} else {
						resp, err := persistence.GetCommandResponse(&proto.CommandRequest{Command: command})
						if err != nil {
							h.logger.Error().Err(err).Msg("error getting command response")
						}
						if err == nil {
							term.Write([]byte(resp.Response))
						}
					}

					lr := &proto.ShellCommandRequest{
						Cmd:  command,
						Guid: perms.Extensions["guid"],
					}

					stats.Increment("ssh.shell_commands")

					go func(in *proto.ShellCommandRequest) {
						if err := persistence.SaveShellCommand(in); err != nil {
							logger.Error().Err(err).Msg("error saving ssh login request")
						}
					}(lr)

					channel.Close()
				case "subsystem":
					// ref https://gist.github.com/Timmmm/f351605579046d0a225685943e884621
					h.logger.Info().Msg("->>>>>>>>>>>>>>> sftp")
				// shell is used: ssh user@host ... then commands are entered
				case "shell":
					for {
						term.Write([]byte("root@localhost:/# "))
						line, err := term.ReadLine()
						if err == io.EOF {
							h.logger.Info().Msg("eof detected, closing")
							sessionTimer.Send("ssh.session_time")
							channel.Close()
							ok = true
							break
						}
						if err != nil {
							h.logger.Error().Err(err).Msg("error running shell")
						}

						resp, err := persistence.GetCommandResponse(&proto.CommandRequest{Command: line})
						if err != nil {
							h.logger.Error().Err(err).Msg("error getting command response")
						}
						if err == nil {
							term.Write([]byte(resp.Response))
						}

						lr := &proto.ShellCommandRequest{
							Cmd:  line,
							Guid: perms.Extensions["guid"],
						}

						stats.Increment("ssh.shell_commands")

						go func(in *proto.ShellCommandRequest) {
							if err := persistence.SaveShellCommand(in); err != nil {
								logger.Error().Err(err).Msg("error saving ssh login request")
							}
						}(lr)

					}
					if len(req.Payload) == 0 {
						ok = true
					}
				case "pty-req":
					// Responding 'ok' here will let the client
					// know we have a pty ready for input
					ok = true
					// Parse body...
					if termEnv, perr := parsePtyRequest(req.Payload); perr != nil {
						h.logger.Info().Err(perr).Msg("malformed pty request")
					} else {
						h.logger.Info().Str("pty-req", termEnv).Msg("pty request")
					}
				default:
					h.logger.Info().Str("type", req.Type).Str("payload", string(req.Payload)).Msg("unknown payload")
				}

				if !ok {
					h.logger.Info().Str("type", req.Type).Msg("declining request")
				}

				req.Reply(ok, nil)
			}
		}(requests)
	}
}

func parseIpPortFrom(conn ssh.ConnMetadata) (string, int) {
	remote := strings.Split(conn.RemoteAddr().String(), ":")
	port, err := strconv.Atoi(remote[1])
	if err != nil {
		port = 0
	}
	return remote[0], port
}

func (h *honeypot) passAuthCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	guid := uuid.NewV4()
	ip, remotePort := parseIpPortFrom(conn)

	cacheKey := fmt.Sprintf("%s+%s", ip, conn.User())
	h.logger.Info().Str("cache-key", cacheKey).Msg("cache-key")
	cacheUUID, retrieved := honeypots.Cache.GetOrSet(cacheKey, guid.String(), ttlcache.WithTTL[string, string](ttlcache.DefaultTTL))
	if retrieved {
		guid, _ = uuid.FromString(cacheUUID.Value())
		h.logger.Info().Str("retrieved-guid", guid.String()).Msg("retrieved-guid")
	}

	lr := &proto.SshLoginRequest{
		RemoteAddr: ip,
		RemotePort: int32(remotePort),
		Username:   conn.User(),
		Guid:       guid.String(),
		Version:    string(conn.ClientVersion()),
		Password:   string(password),
		LoginType:  "password",
	}

	go func(in *proto.SshLoginRequest) {
		if err := persistence.SaveSshLogin(in); err != nil {
			logger.Error().Err(err).Msg("error saving ssh login request")
		}
	}(lr)

	return &ssh.Permissions{Extensions: map[string]string{"guid": guid.String()}}, nil
}

func (h *honeypot) keyAuthCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	guid := uuid.NewV4()
	ip, remotePort := parseIpPortFrom(conn)

	cacheKey := fmt.Sprintf("%s+%s", ip, conn.User())
	h.logger.Info().Str("cache-key", cacheKey).Msg("cache-key")
	cacheUUID, retrieved := honeypots.Cache.GetOrSet(cacheKey, guid.String(), ttlcache.WithTTL[string, string](ttlcache.DefaultTTL))
	if retrieved {
		guid, _ = uuid.FromString(cacheUUID.Value())
		h.logger.Info().Str("retrieved-guid", guid.String()).Msg("retrieved-guid")
	}

	lr := &proto.SshLoginRequest{
		RemoteAddr: ip,
		RemotePort: int32(remotePort),
		Username:   conn.User(),
		Guid:       guid.String(),
		Version:    string(conn.ClientVersion()),
		PublicKey:  key.Marshal(),
		KeyType:    key.Type(),
		LoginType:  "key",
	}

	go func(in *proto.SshLoginRequest) {
		if err := persistence.SaveSshLogin(in); err != nil {
			logger.Error().Err(err).Msg("error saving ssh login request")
		}
	}(lr)

	return &ssh.Permissions{Extensions: map[string]string{"guid": guid.String()}}, nil
}
