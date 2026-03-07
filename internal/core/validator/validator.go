package validator

import (
	"errors"
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTrans "github.com/go-playground/validator/v10/translations/en"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/contract"
)

var (
	// val is the package-level validator instance shared across all calls.
	val = validator.New()

	// trans is the English translator used to produce human-readable error messages.
	trans = registerTranslation()
)

// ValidateStruct validates the given struct against its 'validate' field tags.
// It returns a slice of APIErrorDetail describing each violated constraint,
// or nil if the struct is valid.
func ValidateStruct(input any) []contract.APIErrorDetail {
	var errs []contract.APIErrorDetail
	if err := val.Struct(input); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			errs = translateErrorMessage(validationErrors)
		}
	}

	return errs
}

// translateErrorMessage converts a slice of validator.ValidationErrors into
// APIErrorDetail values with human-readable English messages.
func translateErrorMessage(validationErrors validator.ValidationErrors) []contract.APIErrorDetail {
	var errDetails []contract.APIErrorDetail

	for _, err := range validationErrors {
		errDetails = append(errDetails, contract.APIErrorDetail{
			Field:   err.Field(),
			Message: err.Translate(trans),
			Value:   err.Value(),
		})
	}

	return errDetails
}

// registerTranslation sets up the English translator for the package-level validator,
// registers the default english translations, and configures the validator to use
// the JSON field name (from the 'json' tag) instead of the Go struct field name in error messages.
func registerTranslation() ut.Translator {
	english := en.New()
	universalTranslator := ut.New(english, english)
	trans, _ := universalTranslator.GetTranslator("en")
	_ = enTrans.RegisterDefaultTranslations(val, trans)

	val.RegisterTagNameFunc(func(fld reflect.StructField) string {
		const jsonTagParts = 2
		name := strings.SplitN(fld.Tag.Get("json"), ",", jsonTagParts)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return trans
}
