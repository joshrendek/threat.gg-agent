package ftp

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/joshrendek/hnypots-agent/persistence"

	"github.com/prometheus/common/log"
	uuid "github.com/satori/go.uuid"
)

type LoginDetails struct {
	Username   string
	Password   string
	RemoteAddr string
}

var (
	loginDetails = make(chan LoginDetails)
)

func CommandReceiver() {

}

func LoginReceiver() {
	for l := range loginDetails {
		guid := uuid.NewV4()
		remoteAddr := strings.Split(l.RemoteAddr, ":")
		log.Infof("remoteAddr: +v\n", remoteAddr)
		attack := &persistence.FtpAttack{}
		attack.Guid = guid.String()
		attack.RemoteAddr = remoteAddr[0]
		attack.Username = l.Username
		attack.Password = l.Password
		log.Infof("login-details: %+v\n", l)
		attack.Save()
	}
	//credentials := <-loginDetails
	//fmt.Println("login received")
	//fmt.Println(credentials)
	//prefix := "honeypot."
	//statsdclient := statsd.NewStatsdClient("stats.sysward.com:8125", prefix)
	//statsdclient.CreateSocket()
	//statsdclient.Incr("ftp.logins", 1)
	//statsdclient.Close()

}

func Start() {
	fmt.Println("Starting up FTP server")
	port := ":21"
	if os.Getenv("FTP_PORT") != "" {
		port = ":" + os.Getenv("FTP_PORT")
	}
	ln, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	go LoginReceiver()

	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		fmt.Printf("Connection from %v established.\n", c.RemoteAddr())
		go HandleConnection(c)
	}

}
