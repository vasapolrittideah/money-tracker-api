package middleware

import (
	"context"
	"net/http"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	appi18n "github.com/vasapolrittideah/money-tracker-api/internal/core/i18n"
)

// I18n reads the Accept-Language header and stores a Localizer in the request
// context so that handlers can call appi18n.LocalizeError(r.Context(), err).
func I18n(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := r.Header.Get("Accept-Language")
		localizer := appi18n.NewLocalizer(lang)
		ctx := context.WithValue(r.Context(), localizerContextKey, localizer)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type i18nContextKey string

const localizerContextKey i18nContextKey = "i18n_localizer"

// LocalizerFromContext retrieves the Localizer stored by the middleware.
func LocalizerFromContext(ctx context.Context) (*i18n.Localizer, bool) {
	l, ok := ctx.Value(localizerContextKey).(*i18n.Localizer)
	return l, ok
}

// LocalizeError translates an error message using the Localizer in the context.
// Falls back to err.Error() if no localizer is present or the message ID is unknown.
func LocalizeError(ctx context.Context, err error) string {
	l, ok := LocalizerFromContext(ctx)
	if !ok {
		return err.Error()
	}
	msg, locErr := l.Localize(&i18n.LocalizeConfig{MessageID: err.Error()})
	if locErr != nil {
		return err.Error()
	}
	return msg
}
