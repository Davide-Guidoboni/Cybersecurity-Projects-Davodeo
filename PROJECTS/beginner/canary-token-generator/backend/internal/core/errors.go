// ©AngelaMos | 2026
// errors.go

package core

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrNotFound     = errors.New("resource not found")
	ErrDuplicateKey = errors.New("duplicate key violation")
	ErrForeignKey   = errors.New("foreign key violation")
	ErrInvalidInput = errors.New("invalid input")
	ErrInternal     = errors.New("internal server error")
	ErrConflict     = errors.New("resource conflict")
	ErrRateLimited  = errors.New("rate limit exceeded")
)

type AppError struct {
	Err        error  `json:"-"`
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
}

func (e *AppError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "unknown error"
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func NewAppError(
	err error,
	message string,
	statusCode int,
	code string,
) *AppError {
	return &AppError{
		Err:        err,
		Message:    message,
		StatusCode: statusCode,
		Code:       code,
	}
}

func NotFoundError(resource string) *AppError {
	return &AppError{
		Err:        ErrNotFound,
		Message:    fmt.Sprintf("%s not found", resource),
		StatusCode: http.StatusNotFound,
		Code:       "NOT_FOUND",
	}
}

func DuplicateError(field string) *AppError {
	return &AppError{
		Err:        ErrDuplicateKey,
		Message:    fmt.Sprintf("%s already exists", field),
		StatusCode: http.StatusConflict,
		Code:       "DUPLICATE",
	}
}

func ValidationError(message string) *AppError {
	return &AppError{
		Err:        ErrInvalidInput,
		Message:    message,
		StatusCode: http.StatusBadRequest,
		Code:       "VALIDATION_ERROR",
	}
}

func InternalError(err error) *AppError {
	return &AppError{
		Err:        err,
		Message:    "internal server error",
		StatusCode: http.StatusInternalServerError,
		Code:       "INTERNAL_ERROR",
	}
}

func RateLimitError() *AppError {
	return &AppError{
		Err:        ErrRateLimited,
		Message:    "too many requests",
		StatusCode: http.StatusTooManyRequests,
		Code:       "RATE_LIMITED",
	}
}

func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

func GetAppError(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return InternalError(err)
}
