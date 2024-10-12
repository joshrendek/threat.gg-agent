package main

import (
	"flag"
	"github.com/joshrendek/threat.gg-agent/updater"
	"os/exec"
	"time"

	"github.com/jellydator/ttlcache/v3"

	"github.com/joshrendek/threat.gg-agent/honeypots"

	"github.com/joshrendek/threat.gg-agent/persistence"

	_ "github.com/joshrendek/threat.gg-agent/elasticsearch"
	_ "github.com/joshrendek/threat.gg-agent/ftp"
	_ "github.com/joshrendek/threat.gg-agent/postgres"
	_ "github.com/joshrendek/threat.gg-agent/sshd"
	_ "github.com/joshrendek/threat.gg-agent/webserver"

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

	updater.CheckAndUpdate(Version)

	// nuke tor client at startup from old procs
	exec.Command("killall", "tor").Run()

	cache := ttlcache.New[string, string](
		ttlcache.WithTTL[string, string](5 * time.Minute),
	)

	honeypots.Cache = cache
	go honeypots.Cache.Start()

	if err := persistence.Setup(); err != nil {
		log.Fatal().Err(err).Msg("failed to setup grpc connection")
	}

	// Checkin and make sure we send a ping every few seconds
	go func() {
		for {
			if err := persistence.Connect(); err != nil {
				log.Error().Err(err).Msg("failed to checkin to grpc api")
			}
			time.Sleep(30 * time.Second)
		}
	}()

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
	honeypots.StartHoneypots()

	<-wait
}
