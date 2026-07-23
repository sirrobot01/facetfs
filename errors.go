package facetfs

import (
	"context"
	"errors"
	"fmt"
)

// ErrorCode identifies a filesystem failure by semantics rather than by a wire
// protocol's numeric status.
type ErrorCode string

const (
	ErrNotFound               ErrorCode = "not_found"
	ErrExists                 ErrorCode = "exists"
	ErrNotDirectory           ErrorCode = "not_directory"
	ErrIsDirectory            ErrorCode = "is_directory"
	ErrNotEmpty               ErrorCode = "not_empty"
	ErrAccessDenied           ErrorCode = "access_denied"
	ErrAuthenticationRequired ErrorCode = "authentication_required"
	ErrReadOnly               ErrorCode = "read_only"
	ErrInvalid                ErrorCode = "invalid"
	ErrNameTooLong            ErrorCode = "name_too_long"
	ErrNoSpace                ErrorCode = "no_space"
	ErrQuota                  ErrorCode = "quota"
	ErrTooManyOpenFiles       ErrorCode = "too_many_open_files"
	ErrBusy                   ErrorCode = "busy"
	ErrWouldBlock             ErrorCode = "would_block"
	ErrLockConflict           ErrorCode = "lock_conflict"
	ErrStaleObject            ErrorCode = "stale_object"
	ErrStaleCursor            ErrorCode = "stale_cursor"
	ErrNotSupported           ErrorCode = "not_supported"
	ErrCrossDevice            ErrorCode = "cross_device"
	ErrIO                     ErrorCode = "io"
	ErrCorrupt                ErrorCode = "corrupt"
	ErrCanceled               ErrorCode = "canceled"
	ErrTimeout                ErrorCode = "timeout"
)

func (c ErrorCode) Error() string { return string(c) }

// OpError adds safe operation context while retaining a canonical code and an
// optional internal cause. Frontends should expose Code, not Cause, on the wire.
type OpError struct {
	Code  ErrorCode
	Op    string
	Cause error
}

func (e *OpError) Error() string {
	if e.Op == "" {
		return e.Code.Error()
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Code)
}

func (e *OpError) Unwrap() error { return e.Cause }

func (e *OpError) Is(target error) bool {
	code, ok := target.(ErrorCode)
	return ok && e.Code == code
}

// Wrap adds a canonical code and operation to an internal error.
func Wrap(code ErrorCode, op string, cause error) error {
	return &OpError{Code: code, Op: op, Cause: cause}
}

// CodeOf extracts the canonical code from err. Context termination is
// normalized even when a backend returns context errors directly.
func CodeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return ErrCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	var opErr *OpError
	if errors.As(err, &opErr) {
		return opErr.Code
	}
	var code ErrorCode
	if errors.As(err, &code) {
		return code
	}
	return ErrIO
}
