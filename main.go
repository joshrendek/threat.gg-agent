package main

import (
	"flag"
	"fmt"
	_ "github.com/joshrendek/hnypots-agent/elasticsearch"
	_ "github.com/joshrendek/hnypots-agent/ftp"
	"github.com/joshrendek/hnypots-agent/honeypots"
	"github.com/joshrendek/hnypots-agent/persistence"
	_ "github.com/joshrendek/hnypots-agent/sshd"
	"github.com/joshrendek/hnypots-agent/stats"
	_ "github.com/joshrendek/hnypots-agent/webserver"
	"github.com/rs/zerolog/log"
	"os"
)

var (
	Version        string = "20180604"
	displayVersion bool
	StatsdHost     string
)

func init() {
	log.Logger = log.With().Caller().Logger()
}

func main() {
	flag.BoolVar(&displayVersion, "version", false, "display current version")
	flag.Parse()
	// TODO: make this not crappy
	stats.StatsdHost = StatsdHost
	stats.Setup()
	log.Print("statsd host: ", StatsdHost)
	if displayVersion {
		fmt.Println("Version: ", Version)
		os.Exit(0)
	}
	stats.Increment("startup")
	wait := make(chan bool, 1)
	persistence.RegisterHoneypot()
	honeypots.StartHoneypots()
	<-wait
}
