package sshd

import (
	"bufio"
	"bytes"
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

	"github.com/davecgh/go-spew/spew"

	"github.com/joshrendek/threat.gg-agent/persistence"

	"context"
	"net"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/stats"
	"github.com/rs/zerolog"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const DEFAULT_SHELL = "bash"

var (
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
	fmt.Println("****************")

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
		PasswordCallback:  passAuthCallback,
		PublicKeyCallback: keyAuthCallback,
		ServerVersion:     "SSH-2.0-OpenSSH_6.4p1, OpenSSL 1.0.1e-fips 11 Feb 2013", // old and vulnerable!
	}

	// You can generate a keypair with 'ssh-keygen -t rsa -C "test@example.com"'
	privateBytes, err := ioutil.ReadFile("./honeypot_prv")
	if err != nil {
		h.logger.Fatal().Msg("failed to load private key (./honeypot_prv)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		h.logger.Fatal().Msg("failed to parse private key")
	}

	sshConfig.AddHostKey(private)

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
		os.Remove("honeypot_prv")
		os.Remove("honeypot_prv.pub")
	}

	out, err := exec.Command("ssh-keygen", "-t", "rsa", "-q", "-f", "honeypot_prv", "-N", "").CombinedOutput()
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

		httpReq := &persistence.HttpRequest{
			Headers:  toReq.Header,
			URL:      url,
			FormData: toReq.Form,
			Method:   toReq.Method,
			Guid:     perms.Extensions["guid"],
			Hostname: toReq.Host,
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
		httpReq.Save()

		//log.Printf("[ http://%s ] %s", url, body)

		channel.Write(body)
		// make the http request

		//if resp, ok := httpHandler[url]; ok {
		//	channel.Write(resp)
		//} else {
		//	channel.Write([]byte("45.4.5.6"))
		//}
		channel.Close()
	}
}

func (h *honeypot) handleChannels(chans <-chan ssh.NewChannel, perms *ssh.Permissions) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		//if t := newChannel.ChannelType(); t != "session" {
		//	newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		//	continue
		//}
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
				cr := NewCommandService()

				h.logger.Info().Msgf("payload %+v\n", string(req.Payload))
				ok := false
				switch req.Type {
				// exec is used: ssh user@host 'some command'
				case "exec":
					ok = true
					command := string(req.Payload[4 : req.Payload[3]+4])

					//resp := cr.GetCommandResponse(command)
					//term.Write([]byte(resp.Response))

					if strings.Contains(command, "scp") {
						fmt.Println("*********************")
						h.logger.Info().Msg("****************** scp command")
						fmt.Println("*********************")

						// send 10 magic null bytes
						for i := 0; i <= 10; i++ {
							channel.Write([]byte("\x00"))
						}

						b := new(bytes.Buffer)
						size, err := b.ReadFrom(channel)
						if err != nil {
							fmt.Println("ERROR: ", err)
						}
						spew.Dump("size: ", size)
						spew.Dump(b.String())

						//req.Reply(true, nil) // tell the other end that we can run the request

					}

					shellCommand := &persistence.ShellCommand{Cmd: command, Guid: perms.Extensions["guid"]}
					stats.Increment("ssh.shell_commands")
					go shellCommand.Save()

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

						resp := cr.GetCommandResponse(line)
						term.Write([]byte(resp.Response))

						shellCommand := &persistence.ShellCommand{Cmd: line, Guid: perms.Extensions["guid"]}
						stats.Increment("ssh.shell_commands")
						go shellCommand.Save()

						log.Println(line)
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

func passAuthCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	guid := uuid.NewV4()
	ip, remotePort := parseIpPortFrom(conn)
	login := persistence.SshLogin{RemoteAddr: ip,
		RemotePort: remotePort,
		Username:   conn.User(),
		Password:   string(password),
		Guid:       guid.String(),
		Version:    string(conn.ClientVersion()),
		LoginType:  "password",
	}
	login.Save()
	return &ssh.Permissions{Extensions: map[string]string{"guid": guid.String()}}, nil
}

func keyAuthCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	guid := uuid.NewV4()
	ip, remotePort := parseIpPortFrom(conn)
	login := persistence.SshLogin{RemoteAddr: ip,
		RemotePort: remotePort,
		Username:   conn.User(),
		Guid:       guid.String(),
		Version:    string(conn.ClientVersion()),
		PublicKey:  key.Marshal(),
		KeyType:    string(key.Type()),
		LoginType:  "key",
	}
	go login.Save()
	//log.Println("Fail to authenticate", conn, ":", err)
	//return nil, errors.New("invalid authentication")
	return &ssh.Permissions{Extensions: map[string]string{"guid": guid.String()}}, nil
}
