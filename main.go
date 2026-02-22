package main

import (
	"flag"
	"github.com/jellydator/ttlcache/v3"
	"github.com/joshrendek/threat.gg-agent/elasticsearch"
	"github.com/joshrendek/threat.gg-agent/ftp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/kubernetes"
	"github.com/joshrendek/threat.gg-agent/openclaw"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/postgres"
	"github.com/joshrendek/threat.gg-agent/sshd"
	"github.com/joshrendek/threat.gg-agent/updater"
	"github.com/rs/zerolog/log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"time"
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

	go func() {
		for {
			updated, err := updater.CheckAndUpdate(Version)
			if err != nil {
				log.Error().Err(err).Msg("failed to check and update")
			}

			if updated {
				os.Exit(0)
			}
			time.Sleep(15 * time.Minute)
		}
	}()

	go func() {
		log.Info().Err(http.ListenAndServe("localhost:6060", nil)).Msg("pprof")
	}()

	// nuke tor client at startup from old procs
	exec.Command("killall", "tor").Run()

	// cache for ssh sessions
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
	wait := make(chan bool, 1)
	honeypots.Register(kubernetes.New())
	honeypots.Register(postgres.New())
	honeypots.Register(elasticsearch.New())
	honeypots.Register(ftp.New())
	honeypots.Register(sshd.New())
	honeypots.Register(openclaw.New())
	honeypots.StartHoneypots()

	<-wait
}
