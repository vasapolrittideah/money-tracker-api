package contract

import (
	"net/http"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/utils"
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

// WriteSuccessResponse writes a successful API response with the given data.
func WriteSuccessResponse(w http.ResponseWriter, data any) {
	if err := utils.WriteJSON(w, http.StatusOK, APIResponse{
		Data:      data,
		Error:     nil,
		Timestamp: time.Now(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// WriteErrorResponse writes an error API response with the given status, message,
// and optional field-level details.
func WriteErrorResponse(w http.ResponseWriter, status int, message string, details []APIErrorDetail) {
	if err := utils.WriteJSON(w, status, APIResponse{
		Data: nil,
		Error: &APIError{
			Status:  status,
			Message: message,
			Details: details,
		},
		Timestamp: time.Now(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// WriteValidationErrorResponse writes a 400 Bad Request response with validation error details.
func WriteValidationErrorResponse(w http.ResponseWriter, details []APIErrorDetail) {
	WriteErrorResponse(w, http.StatusBadRequest, "validation failed", details)
}

// WriteNotFoundResponse writes a 404 Not Found response with the given message.
func WriteNotFoundResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusNotFound, message, nil)
}

// WriteUnauthorizedResponse writes a 401 Unauthorized response with the given message.
func WriteUnauthorizedResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusUnauthorized, message, nil)
}

// WriteForbiddenResponse writes a 403 Forbidden response with the given message.
func WriteForbiddenResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusForbidden, message, nil)
}

// WriteBadRequestResponse writes a 400 Bad Request response with the given message.
func WriteBadRequestResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusBadRequest, message, nil)
}

// WritePreconditionFailedResponse writes a 412 Precondition Failed response with the given message.
func WritePreconditionFailedResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusPreconditionFailed, message, nil)
}

// WriteInternalErrorResponse writes a 500 Internal Server Error response with the given message.
func WriteInternalErrorResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusInternalServerError, message, nil)
}

// WriteConflictResponse writes a 409 Conflict response with the given message.
func WriteConflictResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusConflict, message, nil)
}
