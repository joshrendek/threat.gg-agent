package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

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

func main() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	logfile = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	config = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			logfile.Println(fmt.Sprintf("Username: %s | Password: %s", c.User(), string(pass)))
			if c.User() == "testuser" && string(pass) == "tiger" {
				return nil, nil

			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}
	privateBytes, err := ioutil.ReadFile("/Users/joshrendek/.ssh/id_rsa")
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
	listener, err := net.Listen("tcp", "0.0.0.0:3333")
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
