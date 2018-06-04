package honeypots

import "github.com/rs/zerolog/log"

type Honeypot interface {
	Start()
	Name() string
}

var (
	honeypots = []Honeypot{}
)

func Register(h Honeypot) {
	honeypots = append(honeypots, h)
}

func StartHoneypots() {
	for _, h := range honeypots {
		log.Info().Str("honeypot", h.Name()).Msg("starting")
		go h.Start()
	}
}
