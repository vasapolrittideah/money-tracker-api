package contract

import "time"

// APIResponse is the standard envelope for all HTTP responses.
// Exactly one of Data or Error will be set - never both.
type APIResponse struct {
	// Data contains the successful response payload, omitted when an error occurs.
	Data any `json:"data,omitempty"`

	// Error contains the error details when an operation fails, omitted on success.
	Error *APIError `json:"error,omitempty"`

	// Timestamp is always included to indicate when the response was generated.
	Timestamp time.Time `json:"timestamp"`
}

// APIError represents a machine-readable error returned inside APIResponse.
type APIError struct {
	// Code is a stable, uppercase error identifier (e.g. "NOT_FOUND").
	Code string `json:"code"`

	// Message is a human-readable description of the error.
	Message string `json:"message"`

	// Details contains field-level validation errors, omitted when empty.
	Details []APIErrorDetail `json:"details,omitempty"`
}

// APIErrorDetail describes a single field-level error, typically used
// for validation failures.
type APIErrorDetail struct {
	// Field is the name of the field that caused the error (e.g. "email").
	Field string `json:"field"`

	// Message is a human-readable description of the error for this field.
	Message string `json:"message"`

	// Value is the actual value that caused the error, omitted when not applicable.
	Value any `json:"value,omitempty"`
}

// Error code constants used in APIError.Code.
const (
	ErrCodeNotFound           = "NOT_FOUND"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeBadRequest         = "BAD_REQUEST"
	ErrCodePreconditionFailed = "PRECONDITION_FAILED"
	ErrCodeInternal           = "INTERNAL"
	ErrCodeConflict           = "CONFLICT"
)

// NewSuccessResponse creates an APIResponse with the given data payload and no error.
func NewSuccessResponse(data any) APIResponse {
	return APIResponse{
		Data:      data,
		Error:     nil,
		Timestamp: time.Now(),
	}
}

// NewErrorResponse creates an APIResponse with the given error code, message, and
// optional field-level details. Data is always nil for error responses.
func NewErrorResponse(code, message string, details []APIErrorDetail) APIResponse {
	return APIResponse{
		Data: nil,
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: details,
		},
		Timestamp: time.Now(),
	}
}

// NewValidationErrorResponse creates a BAD_REQUEST response populated with
// field-level validation details.
func NewValidationErrorResponse(details []APIErrorDetail) APIResponse {
	return NewErrorResponse(ErrCodeBadRequest, "Validation failed", details)
}

// NewNotFoundResponse creates a NOT_FOUND error response with the given message.
func NewNotFoundResponse(message string) APIResponse {
	return NewErrorResponse(ErrCodeNotFound, message, nil)
}

// NewUnauthorizedResponse creates an UNAUTHORIZED error response with the given message.
func NewUnauthorizedResponse(message string) APIResponse {
	return NewErrorResponse(ErrCodeUnauthorized, message, nil)
}

// NewForbiddenResponse creates a FORBIDDEN error response with the given message.
func NewForbiddenResponse(message string) APIResponse {
	return NewErrorResponse(ErrCodeForbidden, message, nil)
}

// NewPreconditionFailedResponse creates a PRECONDITION_FAILED error response with the given message.
func NewPreconditionFailedResponse(message string) APIResponse {
	return NewErrorResponse(ErrCodePreconditionFailed, message, nil)
}

// NewInternalErrorResponse creates an INTERNAL error response with the given message.
func NewInternalErrorResponse(message string) APIResponse {
	return NewErrorResponse(ErrCodeInternal, message, nil)
}

// NewConflictResponse creates a CONFLICT error response with the given message.
func NewConflictResponse(message string) APIResponse {
	return NewErrorResponse(ErrCodeConflict, message, nil)
}
