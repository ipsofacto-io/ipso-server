package login

import (
	"io"
	"log/slog"

	"golang.org/x/time/rate"
)

type rateLimit = rate.Limit

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
