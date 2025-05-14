package domain

import "github.com/vasapolrittideah/money-tracker-api/shared/constants/error_code"

type AppStatus string

const (
	StatusSuccess AppStatus = "SUCCESS"
	StatusFailure AppStatus = "FAILURE"
	StatusError   AppStatus = "ERROR"
)

type response struct {
	Status       AppStatus            `json:"status"`
	ErrorCode    error_code.ErrorCode `json:"error_code,omitempty"`
	ErrorMessage string               `json:"error_message,omitempty"`
	ErrorDetails any                  `json:"error_details,omitempty"`
	Data         any                  `json:"data"`
}

type InvalidField struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func SuccessResponse(data any) response {
	return response{
		Status: StatusSuccess,
		Data:   data,
	}
}

func ErrorResponse(errorCode error_code.ErrorCode) response {
	return response{
		Status:       StatusError,
		ErrorCode:    errorCode,
		ErrorMessage: errorCode.Message(),
	}
}

func InvalidFieldResponse(invalidFields []InvalidField) response {
	return response{
		Status:       StatusFailure,
		ErrorCode:    error_code.ValidationError,
		ErrorMessage: error_code.ValidationError.Message(),
		ErrorDetails: invalidFields,
	}
}
