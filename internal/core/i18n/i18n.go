package appi18n

import (
	"embed"
	"encoding/json"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

// localeFS holds the compiled-in translation files under locales/.
// The //go:embed directive embeds them into the binary at build time so that
// no external files need to be present at runtime.
//
//go:embed locales/*.json
var localeFS embed.FS

// bundle is the application-wide i18n.Bundle. It is populated by Init and then
// treated as read-only, making it safe to share across goroutines without a mutex.
var bundle *i18n.Bundle

// Init loads all locale files into the package-level bundle.
// It must be called exactly once before any request is handled.
//
// Thai is used as the default language when no matching translation is found.
func Init() {
	bundle = i18n.NewBundle(language.Thai)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)
	bundle.LoadMessageFileFS(localeFS, "locales/en.json")
	bundle.LoadMessageFileFS(localeFS, "locales/th.json")
}

// NewLocalizer returns a Localizer configured for the given language tag string
// (e.g. "th", "en", "en-US"). go-i18n falls back to the bundle's default
// language when the requested language has no matching message file.
func NewLocalizer(lang string) *i18n.Localizer {
	return i18n.NewLocalizer(bundle, lang)
}
