package elasticsearch

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/joshrendek/hnypots-agent/persistence"

	"github.com/prometheus/common/log"
	uuid "github.com/satori/go.uuid"
)

var resp = `{
  "name": "Y6xYwin",
  "cluster_name": "elasticsearch",
  "cluster_uuid": "t-skKQkIQJmBkVlictA8mw",
  "version": {
    "number": "2.4.0",
    "build_hash": "780f8c4",
    "build_date": "2015-04-28T17:43:27.229Z",
    "build_snapshot": false,
    "lucene_version": "6.5.0"
  },
  "tagline": "You Know, for Search"
}`

type ES struct{}

func (e *ES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	guid := uuid.NewV4()
	attack := &persistence.EsAttack{}
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

	r.ParseForm()
	log.Infof("[elasticsearch] path: %s - remote_ip: %s - client: %s", r.RequestURI, r.RemoteAddr, r.UserAgent())
	for k, v := range r.Header {
		attack.Headers[k] = v[0]
		log.Infof("[elasticsearch] |----> header: %s -> %s", k, v)
	}
	for k, v := range r.Form {
		attack.FormData[k] = v[0]
		log.Infof("[elasticsearch] |----> form: %s -> %s", k, v)
	}
	//log.Infof("%+v\n", attack)
	attack.Save()
	fmt.Fprintf(w, resp)
}

func Start() {
	//http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	//})

	log.Fatal(http.ListenAndServe(":9200", &ES{}))
}
