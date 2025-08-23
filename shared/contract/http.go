package contract

import "time"

// APIResponse represents the response structure for the API.
type APIResponse struct {
	Data      any       `json:"data,omitempty"`
	Error     *APIError `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// APIError represents the error structure for the API.
type APIError struct {
	Code    string               `json:"code"`
	Message string               `json:"message"`
	Details []APIValidationError `json:"details,omitempty"`
}

// APIValidationError represents a validation error for the API.
type APIValidationError struct {
	Field   string `json:"field"`
	Message string `json:"error"`
	Value   any    `json:"value,omitempty"`
}

const (
	ErrorCodeValidation   = "VALIDATION_ERROR"
	ErrorCodeNotFound     = "NOT_FOUND"
	ErrorCodeUnauthorized = "UNAUTHORIZED"
	ErrorCodeForbidden    = "FORBIDDEN"
	ErrorCodeInternal     = "INTERNAL_ERROR"
	ErrorCodeBadRequest   = "BAD_REQUEST"
	ErrorCodeConflict     = "CONFLICT"
	ErrorCodeRateLimit    = "RATE_LIMIT_EXCEEDED"
)
