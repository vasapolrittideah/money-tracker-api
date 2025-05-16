package validator

import (
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTranslations "github.com/go-playground/validator/v10/translations/en"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/response"
)

var (
	val   *validator.Validate
	trans ut.Translator
	once  sync.Once
)

func InitValidator() {
	once.Do(func() {
		val = validator.New()
		trans = registerTranslations()
	})
}

func ValidateStruct(i any) (errs []response.InvalidField) {
	if err := val.Struct(i); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			errs = translateErrorMessage(validationErrors)
		}
	}

	return
}

func translateErrorMessage(validationErrors validator.ValidationErrors) (errs []response.InvalidField) {
	var invalidField response.InvalidField
	for _, err := range validationErrors {
		invalidField = response.InvalidField{
			Field:  err.Field(),
			Reason: err.Translate(trans),
		}
		errs = append(errs, invalidField)
	}

	return
}

func registerTranslations() ut.Translator {
	english := en.New()
	universalTranslator := ut.New(english, english)
	trans, _ := universalTranslator.GetTranslator("en")
	_ = enTranslations.RegisterDefaultTranslations(val, trans)

	val.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return trans
}
