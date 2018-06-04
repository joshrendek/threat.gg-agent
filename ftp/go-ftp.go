package ftp

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/joshrendek/hnypots-agent/persistence"

	"github.com/joshrendek/hnypots-agent/honeypots"
	"github.com/rs/zerolog"
	"github.com/satori/go.uuid"
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

func LoginReceiver(logger zerolog.Logger) {
	for l := range loginDetails {
		guid := uuid.NewV4()
		remoteAddr := strings.Split(l.RemoteAddr, ":")
		logger.Info().Str("remote_ip", remoteAddr[0]).Msg("connection started")
		attack := &persistence.FtpAttack{}
		attack.Guid = guid.String()
		attack.RemoteAddr = remoteAddr[0]
		attack.Username = l.Username
		attack.Password = l.Password
		logger.Info().Msgf("login details: %+v\n", l)
		attack.Save()
	}
}

type honeypot struct {
	logger zerolog.Logger
}

func init() {
	honeypots.Register(&honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "ftp").Logger()})
}

func (h *honeypot) Name() string {
	return "ftp"
}

func (h *honeypot) Start() {
	port := ":21"
	if os.Getenv("FTP_PORT") != "" {
		port = ":" + os.Getenv("FTP_PORT")
	}
	ln, err := net.Listen("tcp", port)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start")
		os.Exit(1)
	}

	go LoginReceiver(h.logger)

	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		h.logger.Info().Str("remote_ip", c.RemoteAddr().String()).Msg("connection established")
		go HandleConnection(c, h.logger)
	}

}
