package stats

import (
	"github.com/rs/zerolog"
	//"github.com/rs/zerolog/log"
	//"gopkg.in/alexcesaro/statsd.v2"
	//"gopkg.in/alexcesaro/statsd.v2"
	//"gopkg.in/alexcesaro/statsd.v2"

	"github.com/quipo/statsd"
	"os"
)

var (
	StatsdHost string
	c          *statsd.StatsdClient
	logger     = zerolog.New(os.Stdout).With().Caller().Str("stats", "").Logger()
)

func Setup() {
	c = statsd.NewStatsdClient(StatsdHost, "honeypot")
	logger.Print("statsd host: ", StatsdHost)
}

func Increment(key string) {
	c.Incr(key, 1)
}

func Timing(bucket string) {
	//c.NewTiming().Send("honeypot." + bucket)
}

type fake struct {
}

func (f *fake) Send(s string) {

}

func NewTiming() *fake {
	//return c.NewTiming()
	return &fake{}
}
