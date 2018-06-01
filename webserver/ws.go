package webserver

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/joshrendek/hnypots-agent/persistence"

	"github.com/prometheus/common/log"
	uuid "github.com/satori/go.uuid"
)

func Start() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		guid := uuid.NewV4()
		attack := &persistence.HttpAttack{}
		attack.Headers = map[string]string{}
		attack.FormData = map[string]string{}
		attack.Guid = guid.String()
		attack.Hostname = r.Host
		attack.Method = r.Method
		attack.UserAgent = r.UserAgent()
		user, pass, ok := r.BasicAuth()
		if ok {
			attack.Username = user
			attack.Password = pass
		}
		ip := r.RemoteAddr
		x := strings.Split(ip, ":")
		attack.RemoteAddr = x[0]

		w.Header().Set("Server", "nginx/1.0.0")
		r.ParseForm()

		log.Infof("[web-server] path: %s - remote_ip: %s - client: %s - host: %s", r.RequestURI, r.RemoteAddr, r.UserAgent(), r.Host)
		for k, v := range r.Header {
			attack.Headers[k] = v[0]
			log.Infof("[web-server] |----> header: %s -> %s", k, v)
		}
		for k, v := range r.Form {
			attack.FormData[k] = v[0]
			log.Infof("[web-server] |----> form: %s -> %s", k, v)
		}
		//log.Infof("%+v\n", attack)
		attack.Save()
		fmt.Fprintf(w, "Hello World")
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
