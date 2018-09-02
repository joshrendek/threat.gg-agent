package stats

import (
	"github.com/rs/zerolog"
	//"github.com/rs/zerolog/log"
	//"gopkg.in/alexcesaro/statsd.v2"
	//"gopkg.in/alexcesaro/statsd.v2"
	"os"
)

var (
	StatsdHost string
	//c          *statsd.Client
	logger = zerolog.New(os.Stdout).With().Caller().Str("stats", "").Logger()
)

func Setup() {
	//var err error
	//c, err = statsd.New(statsd.Address(StatsdHost))
	//if err != nil {
	//	// If nothing is listening on the target port, an error is returned and
	//	// the returned client does nothing but is still usable. So we can
	//	// just log the error and go on.
	//	log.Print(err)
	//}
	logger.Print("statsd host: ", StatsdHost)
}

func Increment(key string) {
	//c.Increment("honeypot." + key)
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
