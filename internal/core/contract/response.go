package contract

import (
	"net/http"
	"time"
)

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
	// Status is the HTTP status code associated with the error (e.g. 404).
	Status int `json:"status"`

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
func NewErrorResponse(status int, message string, details []APIErrorDetail) APIResponse {
	return APIResponse{
		Data: nil,
		Error: &APIError{
			Status:  status,
			Message: message,
			Details: details,
		},
		Timestamp: time.Now(),
	}
}

// NewValidationErrorResponse creates a BAD_REQUEST response populated with
// field-level validation details.
func NewValidationErrorResponse(details []APIErrorDetail) APIResponse {
	return NewErrorResponse(http.StatusBadRequest, "Validation failed", details)
}

// NewNotFoundResponse creates a NOT_FOUND error response with the given message.
func NewNotFoundResponse(message string) APIResponse {
	return NewErrorResponse(http.StatusNotFound, message, nil)
}

// NewUnauthorizedResponse creates an UNAUTHORIZED error response with the given message.
func NewUnauthorizedResponse(message string) APIResponse {
	return NewErrorResponse(http.StatusUnauthorized, message, nil)
}

// NewForbiddenResponse creates a FORBIDDEN error response with the given message.
func NewForbiddenResponse(message string) APIResponse {
	return NewErrorResponse(http.StatusForbidden, message, nil)
}

// NewPreconditionFailedResponse creates a PRECONDITION_FAILED error response with the given message.
func NewPreconditionFailedResponse(message string) APIResponse {
	return NewErrorResponse(http.StatusPreconditionFailed, message, nil)
}

// NewInternalErrorResponse creates an INTERNAL error response with the given message.
func NewInternalErrorResponse(message string) APIResponse {
	return NewErrorResponse(http.StatusInternalServerError, message, nil)
}

// NewConflictResponse creates a CONFLICT error response with the given message.
func NewConflictResponse(message string) APIResponse {
	return NewErrorResponse(http.StatusConflict, message, nil)
}
