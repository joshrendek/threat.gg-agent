package main

import (
	"flag"
	"os/exec"

	"github.com/joshrendek/threat.gg-agent/sshd"

	_ "github.com/joshrendek/threat.gg-agent/sshd"

	//_ "github.com/joshrendek/threat.gg-agent/webserver"
	"github.com/rs/zerolog/log"
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

	// nuke tor client at startup from old procs
	exec.Command("killall", "tor").Run()

	// TODO: make this not crappy
	//stats.StatsdHost = StatsdHost
	//stats.Setup()
	//log.Print("statsd host: ", StatsdHost)
	//if displayVersion {
	//	fmt.Println("Version: ", Version)
	//	os.Exit(0)
	//}
	//stats.Increment("startup")

	wait := make(chan bool, 1)
	//persistence.RegisterHoneypot()
	s := sshd.New()
	s.Start()
	//honeypots.StartHoneypots()

	<-wait
}
