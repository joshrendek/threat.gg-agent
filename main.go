package main

import (
	_ "github.com/joshrendek/hnypots-agent/elasticsearch"
	_ "github.com/joshrendek/hnypots-agent/ftp"
	"github.com/joshrendek/hnypots-agent/honeypots"
	"github.com/joshrendek/hnypots-agent/persistence"
	_ "github.com/joshrendek/hnypots-agent/sshd"
	_ "github.com/joshrendek/hnypots-agent/webserver"
)

func main() {
	wait := make(chan bool, 1)
	persistence.RegisterHoneypot()
	honeypots.StartHoneypots()
	<-wait
}
