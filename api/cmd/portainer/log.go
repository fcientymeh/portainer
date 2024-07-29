package main

import (
	"fmt"
	stdlog "log"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

func configureLogger() {
	zerolog.ErrorStackFieldName = "stack_trace"
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	stdlog.SetFlags(0)
	stdlog.SetOutput(log.Logger)

	//log.Logger = log.Logger.With().Logger()
}

func setLoggingLevel(level string) {
	switch level {
	case "ERROR":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "WARN":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "INFO":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "DEBUG":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

func setLoggingMode(mode string) {
	switch mode {
	case "PRETTY":
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:           os.Stderr,
			TimeFormat:    "2006/01/02 03:04:00",
			FormatMessage: formatMessage,
			PartsExclude: []string{
				zerolog.LevelFieldName,
			},
		})
	case "NOCOLOR":
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:           os.Stderr,
			TimeFormat:    "2006/01/02 03:04:00",
			FormatMessage: formatMessage,
			PartsExclude: []string{
				zerolog.LevelFieldName,
			},
			NoColor: true,
		})
	case "JSON":
		log.Logger = log.Output(os.Stderr)
	}
}

func formatMessage(i any) string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%s", i)
}
