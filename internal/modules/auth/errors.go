package auth

import "errors"

var (
	ErrAccountAlreadyExists = errors.New("บัญชีนี้มีอยู่แล้ว")
	ErrInvalidCredentials   = errors.New("อีเมลหรือรหัสผ่านไม่ถูกต้อง")
)
