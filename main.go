package main

import (
	"github.com/joshrendek/hnypots-agent/elasticsearch"
	"github.com/joshrendek/hnypots-agent/ftp"
	"github.com/joshrendek/hnypots-agent/sshd"
	"github.com/joshrendek/hnypots-agent/webserver"
)

func main() {
	wait := make(chan bool, 1)
	go sshd.Start()
	go ftp.Start()
	go elasticsearch.Start()
	go webserver.Start()
	<-wait
}
