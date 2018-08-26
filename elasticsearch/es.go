package elasticsearch

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/joshrendek/hnypots-agent/persistence"

	"github.com/joshrendek/hnypots-agent/honeypots"
	//"github.com/prometheus/common/log"
	"github.com/joshrendek/hnypots-agent/stats"
	"github.com/rs/zerolog"
	"github.com/satori/go.uuid"
	"os"
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

type ES struct {
	logger zerolog.Logger
}

type honeypot struct {
	logger zerolog.Logger
}

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
	requestID := uuid.NewV4()
	requestLogger := e.logger.With().Str("request_id", requestID.String()).Logger()
	requestLogger.Info().Str("path", r.RequestURI).Str("remote_ip", r.RemoteAddr).Str("user_agent", r.UserAgent()).Msg("connection accepted")
	for k, v := range r.Header {
		attack.Headers[k] = v[0]
		requestLogger.Info().Strs(k, v).Msg("header")
	}
	for k, v := range r.Form {
		attack.FormData[k] = v[0]
		requestLogger.Info().Strs(k, v).Msg("form data")
	}
	stats.Increment("elastic_search.requests")
	attack.Save()
	fmt.Fprintf(w, resp)
}

func init() {
	honeypots.Register(&honeypot{logger: zerolog.New(os.Stdout).With().Str("honeypot", "elasticsearch").Logger()})
}

func (h *honeypot) Name() string {
	return "elasticsearch"
}

func (h *honeypot) Start() {
	h.logger.Fatal().Err(http.ListenAndServe(":9200", &ES{logger: h.logger})).Msg("failed to start")
}
