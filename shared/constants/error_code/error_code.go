package error_code

type ErrorCode string

const (
	InvalidRequest     ErrorCode = "INVALID_REQUEST"
	Unauthorized       ErrorCode = "UNAUTHORIZED"
	Forbidden          ErrorCode = "FORBIDDEN"
	NotFound           ErrorCode = "NOT_FOUND"
	Conflict           ErrorCode = "CONFLICT"
	DuplicateUser      ErrorCode = "DUPLICATE_USER"
	ValidationError    ErrorCode = "VALIDATION_ERROR"
	InternalError      ErrorCode = "INTERNAL_ERROR"
	ServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	Timeout            ErrorCode = "TIMEOUT"
	DatabaseError      ErrorCode = "DATABASE_ERROR"
)

var Messages = map[ErrorCode]string{
	InvalidRequest:     "invalid request",
	Unauthorized:       "unauthorized",
	Forbidden:          "forbidden",
	NotFound:           "resource not found",
	Conflict:           "conflict occurred",
	DuplicateUser:      "user already exists",
	ValidationError:    "validation failed",
	InternalError:      "internal server error",
	ServiceUnavailable: "service unavailable",
	Timeout:            "request timeout",
	DatabaseError:      "database error",
}

func (e ErrorCode) Message() string {
	if msg, ok := Messages[e]; ok {
		return msg
	}
	return "unknown error"
}
