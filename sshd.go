package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/go.crypto/ssh/terminal"
)

var sftp_string string = strings.Join([]string{
	"usage: sftp [-1246Cpqrv] [-B buffer_size] [-b batchfile] [-c cipher]",
	"\t   [-D sftp_server_path] [-F ssh_config] [-i identity_file] [-l limit]",
	"\t   [-o ssh_option] [-P port] [-R num_requests] [-S program]",
	"\t   [-s subsystem | sftp_server] host",
	"\tsftp [user@]host[:file ...]",
	"\tsftp [user@]host[:dir[/]]",
	"\tsftp -b batchfile [user@]host\n\r"}, "\n\r")

/*
Docs: https://godoc.org/code.google.com/p/go.crypto/ssh#Config
References:
  * http://stackoverflow.com/questions/10330678/gitolite-pty-allocation-request-failed-on-channel-0
  * http://gitlab.cslabs.clarkson.edu/meshca/golang-ssh-example/commit/556eb3c3bcb58ad457920d894a696e9266bbad36#diff-6
  * https://code.google.com/p/go/source/browse/ssh/example_test.go?repo=crypto
  * https://bitbucket.org/kardianos/vcsguard/src
*/

var config *ssh.ServerConfig
var logfile *log.Logger
var client *http.Client
var err error

type SshLogin struct {
	RemoteAddr string `json:"remote_addr"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type Command struct {
	Cmd string `json:"command"`
}

func PostToApi(endpoint string, post_data *strings.Reader) {
	server_url := os.Getenv("SERVER_URL")
	if server_url == "" {
		server_url = "http://sshpot.com"
	}
	ssh_api := fmt.Sprintf("%s/api/private/%s", server_url, endpoint)
	req, err := http.NewRequest("POST", ssh_api, post_data)
	logfile.Println(fmt.Sprintf("[post] %s", ssh_api))
	_, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
}

func SaveHttpRequest(http_request map[string]string) {
	o, err := json.Marshal(http_request)
	if err != nil {
		panic(err)
	}
	post_data := strings.NewReader(string(o))
	fmt.Println(string(o))
	PostToApi("http", post_data)
}

func (cmd *Command) Save() {
	o, err := json.Marshal(cmd)
	if err != nil {
		panic(err)
	}
	post_data := strings.NewReader(string(o))
	fmt.Println(string(o))

	PostToApi("command", post_data)
}

func (login *SshLogin) Save() {
	o, err := json.Marshal(login)
	if err != nil {
		panic(err)
	}
	post_data := strings.NewReader(string(o))

	PostToApi("ssh", post_data)
}

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func generateSshKey() {
	logfile.Println("[generating ssh keys]")
	if Exists("honeypot") {
		logfile.Println("[removing old keys]")
		os.Remove("honeypot")
		os.Remove("honeypot.pub")
	}

	out, err := exec.Command("ssh-keygen", "-t", "rsa", "-f", "honeypot").CombinedOutput()
	if err != nil {
		logfile.Println(out)
		panic(fmt.Sprintf("Error generating key: %s", err))
	}
}

func main() {
	logfile = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	logfile.Println("[Starting up]")
	generateSshKey()
	client = &http.Client{}
	config = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			logfile.Println(fmt.Sprintf("Remote: %s | Username: %s | Password: %s", c.RemoteAddr(), c.User(), string(pass)))
			addr := strings.Split(c.RemoteAddr().String(), ":")
			login := SshLogin{
				RemoteAddr: addr[0],
				Username:   c.User(),
				Password:   string(pass),
			}
			go login.Save()
			return nil, nil //fmt.Errorf("password rejected for %q", c.User())
		},
	}
	privateBytes, err := ioutil.ReadFile("honeypot")
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	port := os.Getenv("PORT")
	if port == "" {
		port = "22"
	}
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		panic("failed to listen for connection")
	}
	logfile.Println("[listening for connections]")
	// Handle connections in a go routine so we can accept multiple connections at once
	HandleConnection(listener)
}

func RunCommand(cmd string) []byte {
	var ret []byte
	switch cmd {
	case "uname":
		ret = []byte("Linux\n\r")
	case "whoami":
		ret = []byte("root\n\r")
	case "service iptables stop":
		ret = []byte("iptables: unrecognized service\n\r")
	case "sftp":
		ret = []byte(sftp_string)
	}
	return ret
}

func HandleSshRequests(channel ssh.Channel, in <-chan *ssh.Request, term *terminal.Terminal) {
	for req := range in {
		ok := false
		logfile.Println("[request " + req.Type + "]: " + string(req.Payload))
		switch req.Type {
		case "shell":
			// hacky way to get around presenting the correct prompt
			channel.Write([]byte("root@web1:/root# "))
			term.SetPrompt("root@web1:/root# ")
		case "exec":
			term.SetPrompt("")
			fmt.Println(req)
			channel.Write(RunCommand(string(req.Payload[4:])))
			// close after executing their one off command
			channel.Close()
		}
		/* this condition set and reply is needed to allow a PTY */
		ok = true
		req.Reply(ok, nil)
	}
}

func HandleTcpReading(channel ssh.Channel, term *terminal.Terminal, http map[string]string) {
	defer channel.Close()
	for {
		line, err := term.ReadLine()
		if err != nil {
			break
		}
		logfile.Println(line)
		if line == "" {
			channel.Close()
			return
		}

		if strings.Contains(line, ":") {
			kv := strings.Split(line, ":")
			http[kv[0]] = strings.TrimSpace(kv[1])
		} else {
			kv := strings.Fields(line)
			if kv[0] == "POST" || kv[0] == "GET" {
				http["Method"] = kv[0]
				http["URI"] = kv[1]
			} else {
				http[kv[0]] = kv[1]
			}
		}
	}
}

func HandleTerminalReading(channel ssh.Channel, term *terminal.Terminal) {
	defer channel.Close()
	for {
		line, err := term.ReadLine()
		if err != nil {
			break
		}

		cmd_log := Command{Cmd: string(line)}

		if strings.Contains(string(line), "exit") {
			logfile.Println("[exit requested]")
			channel.Close()
		}

		if line == "passwd" {
			line, _ := term.ReadPassword("Enter new UNIX password: ")
			logfile.Println("[password changed]: " + line)
			line, _ = term.ReadPassword("Retype new UNIX password: ")
			logfile.Println("[password changed confirmation]: " + line)
			term.Write([]byte("passwd: password updated successfully\r\n"))
			cmd_log.Cmd += " " + line
		} else {
			term.Write(RunCommand(line))
		}
		cmd_log.Save()
		logfile.Println(line)
	}

}

func HandleConnection(listener net.Listener) {
	for {
		nConn, err := listener.Accept()
		go func() {
			if err != nil {
				panic("failed to accept incoming connection")
			}
			// Before use, a handshake must be performed on the incoming
			// net.Conn.
			_, chans, _, err := ssh.NewServerConn(nConn, config)
			if err == io.EOF {
				return
			}

			if err != nil {
				logfile.Printf("Handshake error: %s", err)
			}
			for newChannel := range chans {
				channel, requests, err := newChannel.Accept()
				if err != nil {
					logfile.Println("[fatal] could not accept channel.")
					continue
				}

				var term *terminal.Terminal
				term = terminal.NewTerminal(channel, "")
				go HandleSshRequests(channel, requests, term)

				logfile.Println("[channelType]: " + newChannel.ChannelType())

				//newChannel.Reject(ssh.ConnectionFailed, "")
				// Sessions have out-of-band requests such as "shell",
				// "pty-req" and "env".

				if newChannel.ChannelType() == "direct-tcpip" {
					http_request := make(map[string]string)
					HandleTcpReading(channel, term, http_request)
					go SaveHttpRequest(http_request)
				} else {
					go HandleTerminalReading(channel, term)
				}

			}
		}()
	}
}
