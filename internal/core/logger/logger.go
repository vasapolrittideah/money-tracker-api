package logger

import (
	"os"

	"github.com/rs/zerolog"
)

var Logger zerolog.Logger

func Init(isDev bool) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if isDev {
		Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	} else {
		Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
}
