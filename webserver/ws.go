package webserver

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/joshrendek/hnypots-agent/persistence"

	"github.com/joshrendek/hnypots-agent/honeypots"
	"github.com/rs/zerolog"
	"github.com/satori/go.uuid"
	"os"
)

type honeypot struct {
	logger zerolog.Logger
}

func init() {
	honeypots.Register(&honeypot{logger: zerolog.New(os.Stdout).With().Str("honeypot", "webserver").Logger()})
}

func (h *honeypot) Name() string {
	return "webserver"
}

func (h *honeypot) Start() {
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

		requestLogger := h.logger.With().Str("request_id", guid.String()).Logger()
		requestLogger.Info().Str("path", r.RequestURI).Str("remote_ip", r.RemoteAddr).Str("user_agent", r.UserAgent()).
			Str("host", r.Host).Msg("connection accepted")
		for k, v := range r.Header {
			attack.Headers[k] = v[0]
			requestLogger.Info().Strs(k, v).Msg("header")
		}
		for k, v := range r.Form {
			attack.FormData[k] = v[0]
			requestLogger.Info().Strs(k, v).Msg("header")
		}
		attack.Save()
		fmt.Fprintf(w, "Hello World")
	})

	h.logger.Fatal().Err(http.ListenAndServe(":8080", nil)).Msg("failed to start")
}
