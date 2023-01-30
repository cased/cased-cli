package cmd

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	fileLogger zerolog.Logger
	logger     zerolog.Logger
)

func init() {
	initLog()
}

// initLog setup logging facilities
func initLog() {
	// Console logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// If DEBUG_FILE is set we log debug messages to the given file.
	if dbgFile := os.Getenv("DEBUG_FILE"); dbgFile != "" {
		file, err := os.OpenFile(
			dbgFile,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0664,
		)

		if err != nil {
			log.Fatal().Msg(err.Error())
		}

		fileLogger = zerolog.New(
			zerolog.ConsoleWriter{Out: file, NoColor: true}).Level(zerolog.InfoLevel)

		// Log level: "trace", "debug", "info", "warn", "error", "fatal, "panic"
		if dbgLevel := os.Getenv("DEBUG_LEVEL"); dbgLevel != "" {
			if lvl, err := zerolog.ParseLevel(dbgLevel); err == nil {
				fileLogger = fileLogger.Level(lvl)
			} else {
				log.Error().Msgf("Invalid log level: %s", dbgLevel)
			}
		}
	} else {
		fileLogger = zerolog.Nop()
	}
}
