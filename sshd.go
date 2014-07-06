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
	"strings"

	"code.google.com/p/go.crypto/ssh"
)

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

type SshLogin struct {
	RemoteAddr string
	Username   string
	Password   string
}

func (login *SshLogin) Save() {
	o, err := json.Marshal(login)
	if err != nil {
		panic(err)
	}
	post_data := strings.NewReader(string(o))
	req, err := http.NewRequest("POST", "http://sshpot.com/api/private/ssh", post_data)
	fmt.Println(fmt.Sprintf("[post] %s", "http://sshpot.com/api/private/ssh"))
	_, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
}

var client *http.Client

func main() {
	logfile = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	logfile.Println("[Starting up]")
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
			return nil, fmt.Errorf("password rejected for %q", c.User())
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
	// Handle connections in a go routine so we can accept multiple connections at once
	HandleConnection(listener)
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
			// immediately close after taking their password
			for newChannel := range chans {
				/*_, _, err := newChannel.Accept()*/
				if err != nil {
					panic("could not accept channel.")
				}

				newChannel.Reject(ssh.ConnectionFailed, "")
			}
		}()
	}
}
