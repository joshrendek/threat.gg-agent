package elasticsearch

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/stats"

	//"github.com/prometheus/common/log"
	"os"

	"github.com/rs/zerolog"
	"github.com/satori/go.uuid"
)

const resp = `{
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

var (
	logger = zerolog.New(os.Stdout).With().Caller().Str("elasticsearch", "").Logger()
)

type ES struct {
	logger zerolog.Logger
}

type honeypot struct {
	logger zerolog.Logger
}

func (e *ES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	guid := uuid.NewV4()

	httpReq := &proto.ElasticsearchRequest{
		Headers:   persistence.HttpToMap(map[string][]string(r.Header)),
		FormData:  persistence.HttpToMap(map[string][]string(r.Form)),
		Method:    r.Method,
		Guid:      guid.String(),
		Hostname:  r.Host,
		UserAgent: r.UserAgent(),
	}

	user, pass, ok := r.BasicAuth()
	if ok {
		httpReq.Username = user
		httpReq.Password = pass
	}
	ip := r.RemoteAddr
	x := strings.Split(ip, ":")
	httpReq.RemoteAddr = x[0]

	stats.Increment("elastic_search.requests")

	go func(in *proto.ElasticsearchRequest) {
		if err := persistence.SaveElasticRequest(in); err != nil {
			logger.Error().Err(err).Msg("error saving http request")
		}
	}(httpReq)

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
