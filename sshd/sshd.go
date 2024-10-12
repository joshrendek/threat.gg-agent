package sshd

import (
	"bufio"
	"encoding/base64"
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

var (
	logger      = zerolog.New(os.Stdout).With().Caller().Str("sshd", "").Logger()
	httpHandler = map[string][]byte{}
	t           *tor.Tor
	dialer      *tor.Dialer
	httpClient  *http.Client
	torEnabled  bool
)

type honeypot struct {
	logger zerolog.Logger
}

func init() {
	honeypots.Register(&honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "ssh").Logger()})
	torEnabled = os.Getenv("TOR_ENABLED") == "true"
}

func New() *honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "ssh").Logger()}
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

		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s", url), nil)
		req.Header = toReq.Header
		resp, err := httpClient.Do(req)
		if err != nil {
			log.Fatalf("Body read error: %s", err)
		}

		defer resp.Body.Close()
		body, err2 := ioutil.ReadAll(resp.Body)
		if err2 != nil {
			log.Fatalf("Body read error: %s", err2)
		}
		encodedBody := base64.StdEncoding.EncodeToString(body)
		httpReq.Response = encodedBody

		go func(in *proto.HttpRequest) {
			if err := persistence.SaveHTTPRequest(in); err != nil {
				logger.Error().Err(err).Msg("error saving http request")
			}
		}(httpReq)

		channel.Write(body)

		channel.Close()
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
			for req := range in {
				term := terminal.NewTerminal(channel, "")

				h.logger.Info().Msgf("payload %+v\n", string(req.Payload))
				ok := false
				switch req.Type {
				// exec is used: ssh user@host 'some command'
				case "exec":
					ok = true
					command := string(req.Payload[4 : req.Payload[3]+4])

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
							for i := 0; i <= tmpFileBytes; i++ {
								t, _ := b.ReadByte()
								bytesRead++
								writer.WriteByte(t)
							}
							fmt.Println("->>>>>>>>>>>>>>> Wrote to: ", tmpFile.Name())

							// read the last null seperator
							b.ReadBytes('\x00')

							h.logger.Info().Str("permissions", tmpFilePerms).
								Str("filename", tmpFileName).
								Int("size-parsed", tmpFileBytes).
								Int("actual-size", bytesRead).
								Msg("received file")
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
					termLen := req.Payload[3]
					termEnv := string(req.Payload[4 : termLen+4])
					h.logger.Info().Str("pty-req", termEnv).Msg("pty request")
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
