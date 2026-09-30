package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

// startTestSSH runs the real honeypot channel handler behind a real SSH
// handshake on a loopback listener and returns a connected client. The stop
// func closes the client and waits for the server goroutine to exit.
func startTestSSH(t *testing.T, guid string) (*ssh.Client, func()) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		server, chans, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		h := &honeypot{logger: zerolog.New(io.Discard)}
		h.handleChannels(chans, &ssh.Permissions{Extensions: map[string]string{"guid": guid}})
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	clientConn, chans, requests, err := ssh.NewClientConn(conn, listener.Addr().String(), &ssh.ClientConfig{User: "root", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		conn.Close()
		listener.Close()
		t.Fatal(err)
	}
	client := ssh.NewClient(clientConn, chans, requests)
	return client, func() {
		client.Close()
		listener.Close()
		<-serverDone
	}
}
