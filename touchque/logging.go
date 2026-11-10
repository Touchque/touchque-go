package touchque

import (
	"context"
	"fmt"
	"log/slog"
)

// sdkLog reports one of the SDK's own problems (a misconfigured guard, a
// failed OnChallenge, a relay without LoginUser) to Config.Logger. A nil
// Logger, the default, logs nothing.
func sdkLog(l *slog.Logger, level slog.Level, msg string, args ...any) {
	if l == nil {
		return
	}
	l.Log(context.Background(), level, msg, args...)
}

// errorText is what a log line says about an error: its type and text, never
// the request it came from.
func errorText(v any) string {
	if e, ok := v.(error); ok {
		return fmt.Sprintf("%T: %s", e, e.Error())
	}
	return fmt.Sprint(v)
}
